// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Validation engine over contracts, service profiles, and optional host state.
//!
//! Validation consumes a derived host contract rather than raw survey evidence so policy-shaped
//! host promises are frozen before workload requirements are compared against them.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use crate::artifacts::contract_v1::HostContractV1;
use crate::artifacts::envelope_v1::{local_artifact_provenance_v1, ArtifactEnvelopeV1};
use crate::artifacts::metadata_v1::DerivationStageV1;
use crate::artifacts::schema_ids_v1::{
    TOP_LEVEL_ARTIFACT_SCHEMA_VERSION, VALIDATION_REPORT_SCHEMA_ID,
};
use crate::artifacts::semantic_hash_v1::{
    semantic_hash_hex_for_contract, semantic_hash_hex_for_service_profile,
    semantic_hash_hex_for_state,
};
use crate::artifacts::service_profile_v1::{
    AssurancePredicateV1, ExplicitAssuranceRequirementV1, ServiceProfileV1,
};
use crate::artifacts::state_v1::{FreshnessStateV1, HostStateV1, StateFieldV1};
use crate::artifacts::validation_report_v1::{
    ValidationBasisV1, ValidationExplanationV1, ValidationModeV1, ValidationReasonCodeV1,
    ValidationRemediationActionV1, ValidationRemediationHintV1, ValidationReportPayloadV1,
    ValidationReportV1, ValidationVerdictV1,
};
use crate::artifacts::validation_v1::{
    validate_host_contract, validate_host_state, validate_service_profile,
    validate_validation_report,
};
use crate::contract::{load_host_contract_artifact_from_path, HostContractPayloadV1};
use crate::extensions::{
    decode_cuda_runtime_requirement_from_value, decode_cuda_runtime_state_from_value,
    decode_cuda_runtime_validation_diagnostic_from_value,
    evaluate_registered_extension_requirement_v1, CudaRuntimeDeviceStateV1, CudaRuntimeStateV1,
    CudaRuntimeValidationCheckpointV1, CudaRuntimeValidationDetailCodeV1,
    CudaRuntimeValidationDiagnosticV1, ExtensionEvaluatorRegistryErrorKindV1,
    ExtensionRequirementEvaluationOutcomeV1, CUDA_RUNTIME_NAMESPACE,
    CUDA_RUNTIME_VALIDATION_DIAGNOSTIC_MODEL_ID,
};
use crate::policy::capability_classes_v1::DerivedCapabilityClaimV1;
use crate::service_profile::load_service_profile_from_path;
use crate::state::load_host_state_from_path;
use crate::survey::{ObservationStateV1, VisibilityScopeV1};
use crate::validate::{ValidationError, ValidationErrorCode};

#[derive(Debug, Clone, PartialEq)]
pub struct ValidationRequestV1 {
    pub contract: HostContractV1,
    pub service_profile: ServiceProfileV1,
    pub host_state: Option<HostStateV1>,
    pub mode: ValidationModeV1,
    pub validated_at: String,
    pub notes: Option<String>,
    pub max_state_age_seconds: Option<u64>,
}

pub fn validate_request_v1(
    request: ValidationRequestV1,
) -> Result<ValidationReportV1, ValidationError> {
    // Validate the request shape first so later phases can assume mode-specific invariants without
    // having to re-check every combination of state input and freshness controls.
    match request.mode {
        ValidationModeV1::ContractOnly => {
            if request.host_state.is_some() {
                return Err(ValidationError::new(
                    ValidationErrorCode::ValidationInputInvalid,
                    "validation_contract_only",
                    "host-state input is not allowed in contract_only mode",
                ));
            }
            if request.max_state_age_seconds.is_some() {
                return Err(ValidationError::new(
                    ValidationErrorCode::ValidationInputInvalid,
                    "validation_contract_only",
                    "max-state-age is not allowed in contract_only mode",
                ));
            }
        }
        ValidationModeV1::StateAware => {
            if request.host_state.is_none() {
                return Err(ValidationError::new(
                    ValidationErrorCode::ValidationInputInvalid,
                    "validation_state_aware",
                    "validation mode state_aware requires a host-state artifact",
                ));
            }
        }
        ValidationModeV1::StateAdvisory | ValidationModeV1::StateRequired => {
            if request.max_state_age_seconds.is_some() && request.host_state.is_none() {
                return Err(ValidationError::new(
                    ValidationErrorCode::ValidationInputInvalid,
                    "validation_state_input",
                    "max-state-age requires a host-state artifact",
                ));
            }
        }
    }

    validate_host_contract(&request.contract).map_err(|error| {
        ValidationError::new(
            ValidationErrorCode::ContractArtifactInvalid,
            "contract_load",
            error.message,
        )
    })?;
    validate_service_profile(&request.service_profile).map_err(|error| {
        ValidationError::new(
            ValidationErrorCode::ServiceProfileArtifactInvalid,
            "service_profile_load",
            error.message,
        )
    })?;
    if let Some(host_state) = request.host_state.as_ref() {
        validate_host_state(host_state).map_err(|error| {
            ValidationError::new(
                ValidationErrorCode::StateArtifactInvalid,
                "state_load",
                error.message,
            )
        })?;
    }

    let contract_payload: HostContractPayloadV1 =
        serde_json::from_value(request.contract.contract.clone()).map_err(|error| {
            ValidationError::new(
                ValidationErrorCode::ContractArtifactInvalid,
                "contract_decode",
                format!("failed to decode host contract payload: {error}"),
            )
        })?;
    if let Some(host_state) = request.host_state.as_ref() {
        if let Some(local_identity) = host_state.state.local_identity.as_ref() {
            let contract_local_stable_id = contract_payload
                .core_contract
                .identity_summary
                .local_stable_id
                .trim();
            let state_local_stable_id = local_identity.local_stable_id.trim();
            if !contract_local_stable_id.is_empty()
                && !state_local_stable_id.is_empty()
                && contract_local_stable_id != state_local_stable_id
            {
                return Err(ValidationError::new(
                    ValidationErrorCode::ValidationInputInvalid,
                    "validation_state_identity",
                    format!(
                        "host-state local identity {} does not match contract local identity {}",
                        host_state.envelope.artifact_id, request.contract.envelope.artifact_id
                    ),
                ));
            }
        }
    }
    let contract_semantic_hash =
        semantic_hash_hex_for_contract(&request.contract).map_err(|error| {
            ValidationError::new(
                ValidationErrorCode::ValidationExecutionFailed,
                "validation_contract_only",
                error.message,
            )
        })?;
    let service_profile_semantic_hash =
        semantic_hash_hex_for_service_profile(&request.service_profile).map_err(|error| {
            ValidationError::new(
                ValidationErrorCode::ValidationExecutionFailed,
                "validation_contract_only",
                error.message,
            )
        })?;
    let state_semantic_hash = request
        .host_state
        .as_ref()
        .map(|state| {
            semantic_hash_hex_for_state(state).map_err(|error| {
                ValidationError::new(
                    ValidationErrorCode::ValidationExecutionFailed,
                    "validation_state_aware",
                    error.message,
                )
            })
        })
        .transpose()?;

    // First evaluate the core contract-versus-profile question for the selected mode, then apply
    // extension requirements and finally attach explanation/hint material.
    let report_payload = match request.mode {
        ValidationModeV1::ContractOnly => {
            evaluate_contract_only(&contract_payload, &request.service_profile)
        }
        ValidationModeV1::StateAware => evaluate_state_mode(
            &contract_payload,
            &request.service_profile,
            request.host_state.as_ref().expect("validated above"),
            ValidationModeV1::StateAware,
            request.max_state_age_seconds,
            &request.validated_at,
        ),
        ValidationModeV1::StateAdvisory => evaluate_with_optional_state(
            &contract_payload,
            &request.service_profile,
            request.host_state.as_ref(),
            ValidationModeV1::StateAdvisory,
            request.max_state_age_seconds,
            &request.validated_at,
        ),
        ValidationModeV1::StateRequired => evaluate_with_optional_state(
            &contract_payload,
            &request.service_profile,
            request.host_state.as_ref(),
            ValidationModeV1::StateRequired,
            request.max_state_age_seconds,
            &request.validated_at,
        ),
    };
    let report_payload = apply_extension_requirements_gate(
        report_payload,
        &request.contract,
        &contract_payload,
        &request.service_profile,
    );
    let report_payload = apply_runtime_extension_state_gate(
        report_payload,
        &request.service_profile,
        request.host_state.as_ref(),
        request.mode,
        request.max_state_age_seconds,
        &request.validated_at,
    );
    let report_payload = attach_validation_explanations_and_hints(report_payload);

    let artifact_id = format!(
        "validation-{}-{}",
        request.contract.envelope.artifact_id, request.service_profile.envelope.artifact_id
    );
    let report = ValidationReportV1 {
        envelope: ArtifactEnvelopeV1 {
            schema_id: VALIDATION_REPORT_SCHEMA_ID.to_string(),
            schema_version: TOP_LEVEL_ARTIFACT_SCHEMA_VERSION,
            artifact_id: artifact_id.clone(),
            provenance: local_artifact_provenance_v1(
                format!("validate:{}", request.mode.as_str()),
                request.validated_at,
                "validate",
                artifact_id,
            ),
            redaction: None,
            signatures: vec![],
        },
        validation_basis: ValidationBasisV1 {
            validation_mode: request.mode,
            contract_artifact_id: request.contract.envelope.artifact_id,
            service_profile_artifact_id: request.service_profile.envelope.artifact_id,
            contract_semantic_hash,
            service_profile_semantic_hash,
            state_artifact_id: request
                .host_state
                .as_ref()
                .map(|state| state.envelope.artifact_id.clone()),
            state_semantic_hash,
            state_observed_at: request
                .host_state
                .as_ref()
                .map(|state| state.state.core_state.freshness.observed_at.clone()),
            state_freshness_state: request
                .host_state
                .as_ref()
                .map(|state| state.state.core_state.freshness.freshness_state),
            max_state_age_seconds: request.max_state_age_seconds,
            validation_engine_id: "fitctl.validate.v1".to_string(),
            validation_engine_version: "1".to_string(),
        },
        report: report_payload,
    };

    validate_validation_report(&report).map_err(|error| {
        ValidationError::new(
            ValidationErrorCode::ValidationReportInvalid,
            "validation_report_emit",
            error.message,
        )
    })?;

    Ok(report)
}

fn attach_validation_explanations_and_hints(
    mut report: ValidationReportPayloadV1,
) -> ValidationReportPayloadV1 {
    report.explanations = build_validation_explanations(&report);
    report.remediation_hints = build_validation_remediation_hints(&report);
    report
}

fn build_validation_explanations(
    report: &ValidationReportPayloadV1,
) -> Vec<ValidationExplanationV1> {
    if let Some(diagnostic) = decode_cuda_runtime_validation_diagnostic_from_report(report) {
        return vec![build_cuda_runtime_validation_explanation(
            &diagnostic,
            report.primary_reason_code,
        )];
    }

    let mut related_requirements = if !report.failed_requirements.is_empty() {
        report.failed_requirements.clone()
    } else {
        report.matched_requirements.clone()
    };
    related_requirements.sort();
    related_requirements.dedup();

    let mut evidence_refs = report.evidence_refs.clone();
    evidence_refs.sort();
    evidence_refs.dedup();

    let mut policy_refs = report.policy_refs.clone();
    policy_refs.sort();
    policy_refs.dedup();

    vec![ValidationExplanationV1 {
        explanation_id: format!("explain-{}", report.primary_reason_code.as_str()),
        reason_code: report.primary_reason_code,
        summary: report.summary.clone(),
        related_requirements,
        evidence_refs,
        policy_refs,
    }]
}

fn build_validation_remediation_hints(
    report: &ValidationReportPayloadV1,
) -> Vec<ValidationRemediationHintV1> {
    use ValidationReasonCodeV1 as Reason;
    use ValidationVerdictV1 as Verdict;

    if matches!(report.verdict, Verdict::Fit) {
        return vec![];
    }

    if let Some(diagnostic) = decode_cuda_runtime_validation_diagnostic_from_report(report) {
        return build_cuda_runtime_validation_remediation_hint(
            &diagnostic,
            report.primary_reason_code,
        )
        .into_iter()
        .collect();
    }

    let hint = match report.primary_reason_code {
        Reason::RequirementsSatisfied => return vec![],
        Reason::RequirementUnsatisfied => ValidationRemediationHintV1 {
            hint_id: "review-failed-requirements".to_string(),
            reason_code: report.primary_reason_code,
            summary: "Review the failed requirement ids and choose a host or profile combination that satisfies them.".to_string(),
            actions: vec![
                ValidationRemediationActionV1 {
                    action_id: "choose-compatible-host-or-profile".to_string(),
                    summary: "Choose a host or service profile whose core requirements align with the failed requirement ids.".to_string(),
                },
                ValidationRemediationActionV1 {
                    action_id: "inspect-failed-requirements".to_string(),
                    summary: "Inspect the failed requirement ids in the validation report before changing policy or deployment targets.".to_string(),
                },
            ],
        },
        Reason::CapabilityUnknown => ValidationRemediationHintV1 {
            hint_id: "review-capability-coverage".to_string(),
            reason_code: report.primary_reason_code,
            summary: "Review the required capability and choose a host contract that explicitly derives it, or narrow the profile if that capability is optional.".to_string(),
            actions: vec![
                ValidationRemediationActionV1 {
                    action_id: "inspect-required-capability".to_string(),
                    summary: "Inspect the failed primary capability requirement in the validation report.".to_string(),
                },
                ValidationRemediationActionV1 {
                    action_id: "select-host-with-required-capability".to_string(),
                    summary: "Select a host whose derived contract exposes the required capability class.".to_string(),
                },
            ],
        },
        Reason::StateMissing => ValidationRemediationHintV1 {
            hint_id: "collect-host-state".to_string(),
            reason_code: report.primary_reason_code,
            summary: "Collect a host-state artifact before rerunning validation when runtime thresholds matter.".to_string(),
            actions: vec![
                ValidationRemediationActionV1 {
                    action_id: "collect-fresh-host-state".to_string(),
                    summary: "Emit a fresh host-state.v2 artifact for the target host.".to_string(),
                },
                ValidationRemediationActionV1 {
                    action_id: "rerun-state-aware-validation".to_string(),
                    summary: "Rerun validation in a state-aware mode once fresh runtime state is available.".to_string(),
                },
            ],
        },
        Reason::StateStale => ValidationRemediationHintV1 {
            hint_id: "refresh-host-state".to_string(),
            reason_code: report.primary_reason_code,
            summary: "Refresh host-state before rerunning validation so runtime-threshold checks use current evidence.".to_string(),
            actions: vec![
                ValidationRemediationActionV1 {
                    action_id: "collect-fresh-host-state".to_string(),
                    summary: "Collect a fresh host-state.v2 artifact for the target host.".to_string(),
                },
                ValidationRemediationActionV1 {
                    action_id: "review-state-age-window".to_string(),
                    summary: "Review the configured max-state-age if the freshness window is stricter than intended.".to_string(),
                },
            ],
        },
        Reason::AssurancePredicateUnresolved => ValidationRemediationHintV1 {
            hint_id: "review-assurance-coverage".to_string(),
            reason_code: report.primary_reason_code,
            summary: "Review the unresolved assurance predicates and supply stronger evidence only if the local policy accepts it.".to_string(),
            actions: vec![
                ValidationRemediationActionV1 {
                    action_id: "inspect-assurance-mismatches".to_string(),
                    summary: "Inspect the assurance mismatch identifiers in the validation report.".to_string(),
                },
                ValidationRemediationActionV1 {
                    action_id: "supply-accepted-assurance-evidence".to_string(),
                    summary: "Supply stronger assurance evidence only if the local trust and validation policy accepts that source.".to_string(),
                },
            ],
        },
        Reason::AssuranceSourceNotAccepted => ValidationRemediationHintV1 {
            hint_id: "review-assurance-source-policy".to_string(),
            reason_code: report.primary_reason_code,
            summary: "Review the assurance-source policy or choose evidence from an accepted source.".to_string(),
            actions: vec![
                ValidationRemediationActionV1 {
                    action_id: "inspect-assurance-policy".to_string(),
                    summary: "Inspect the assurance-related policy references in the validation report.".to_string(),
                },
                ValidationRemediationActionV1 {
                    action_id: "select-accepted-assurance-source".to_string(),
                    summary: "Use assurance evidence from a source accepted by the current service profile and policy.".to_string(),
                },
            ],
        },
        Reason::AssuranceDerivationStageNotAccepted => ValidationRemediationHintV1 {
            hint_id: "review-assurance-derivation-stage".to_string(),
            reason_code: report.primary_reason_code,
            summary: "Review the accepted derivation stages or choose evidence produced at an accepted stage.".to_string(),
            actions: vec![
                ValidationRemediationActionV1 {
                    action_id: "inspect-accepted-derivation-stages".to_string(),
                    summary: "Inspect the service-profile assurance requirements for accepted derivation stages.".to_string(),
                },
                ValidationRemediationActionV1 {
                    action_id: "choose-accepted-derivation-stage".to_string(),
                    summary: "Use evidence produced at a derivation stage accepted by the service profile.".to_string(),
                },
            ],
        },
        Reason::PolicyNotAdmissible => ValidationRemediationHintV1 {
            hint_id: "review-policy-admissibility".to_string(),
            reason_code: report.primary_reason_code,
            summary: "Review the selected policy or choose a host whose derived contract marks the required capability admissible.".to_string(),
            actions: vec![
                ValidationRemediationActionV1 {
                    action_id: "inspect-policy-refs".to_string(),
                    summary: "Inspect the policy refs attached to the validation report before widening policy.".to_string(),
                },
                ValidationRemediationActionV1 {
                    action_id: "select-admissible-host-or-policy".to_string(),
                    summary: "Choose a host or policy pack that derives the required capability as admissible.".to_string(),
                },
            ],
        },
        Reason::NetworkMismatch => ValidationRemediationHintV1 {
            hint_id: "match-network-constraints".to_string(),
            reason_code: report.primary_reason_code,
            summary: "Choose a host whose network summary satisfies the profile, or relax the network requirement if policy allows it.".to_string(),
            actions: vec![
                ValidationRemediationActionV1 {
                    action_id: "inspect-network-requirements".to_string(),
                    summary: "Inspect the failed network requirement ids in the validation report.".to_string(),
                },
                ValidationRemediationActionV1 {
                    action_id: "select-network-compatible-host".to_string(),
                    summary: "Choose a host whose derived network summary matches the required network constraints.".to_string(),
                },
            ],
        },
        Reason::TopologyMismatch => ValidationRemediationHintV1 {
            hint_id: "match-topology-constraints".to_string(),
            reason_code: report.primary_reason_code,
            summary: "Choose a host whose topology summary satisfies the profile, or relax the topology requirement if policy allows it.".to_string(),
            actions: vec![
                ValidationRemediationActionV1 {
                    action_id: "inspect-topology-requirements".to_string(),
                    summary: "Inspect the failed topology requirement ids in the validation report.".to_string(),
                },
                ValidationRemediationActionV1 {
                    action_id: "select-topology-compatible-host".to_string(),
                    summary: "Choose a host whose topology summary matches the required topology constraints.".to_string(),
                },
            ],
        },
        Reason::CapabilityDegraded => ValidationRemediationHintV1 {
            hint_id: "review-degraded-capability".to_string(),
            reason_code: report.primary_reason_code,
            summary: "Inspect the degraded capability warning and choose a healthier host if degraded operation is unacceptable.".to_string(),
            actions: vec![
                ValidationRemediationActionV1 {
                    action_id: "inspect-degraded-capability-warning".to_string(),
                    summary: "Inspect the validation warnings for degraded capability classes.".to_string(),
                },
                ValidationRemediationActionV1 {
                    action_id: "select-healthier-host".to_string(),
                    summary: "Choose a host whose runtime operability does not degrade the required capability class.".to_string(),
                },
            ],
        },
        Reason::DegradationPathRequired => ValidationRemediationHintV1 {
            hint_id: "review-selected-degradation-tier".to_string(),
            reason_code: report.primary_reason_code,
            summary: "Review the selected degradation tier before relying on degraded operation for admission.".to_string(),
            actions: vec![
                ValidationRemediationActionV1 {
                    action_id: "inspect-selected-degradation-tier".to_string(),
                    summary: "Inspect the selected degradation tier and the matched degradation requirement in the validation report.".to_string(),
                },
                ValidationRemediationActionV1 {
                    action_id: "select-full-capability-host-if-needed".to_string(),
                    summary: "Choose a host whose primary capability is admissible if degraded operation is not acceptable.".to_string(),
                },
            ],
        },
        Reason::DegradationPathUnavailable => ValidationRemediationHintV1 {
            hint_id: "review-degradation-coverage".to_string(),
            reason_code: report.primary_reason_code,
            summary: "Review the failed fallback tiers named in the validation summary and choose a host, policy, or profile combination that makes either the primary capability or an allowed fallback admissible.".to_string(),
            actions: vec![
                ValidationRemediationActionV1 {
                    action_id: "inspect-degradation-ladder".to_string(),
                    summary: "Inspect the failed primary capability and the degradation tiers named in the validation report summary.".to_string(),
                },
                ValidationRemediationActionV1 {
                    action_id: "select-admissible-host-policy-or-profile".to_string(),
                    summary: "Choose a host, policy, or profile combination that makes the primary capability or an allowed fallback admissible.".to_string(),
                },
            ],
        },
        Reason::EvidenceIncomplete => ValidationRemediationHintV1 {
            hint_id: "complete-required-evidence".to_string(),
            reason_code: report.primary_reason_code,
            summary: "Collect the missing validation evidence or resolve the incomplete host classification before rerunning validation.".to_string(),
            actions: vec![
                ValidationRemediationActionV1 {
                    action_id: "collect-missing-evidence".to_string(),
                    summary: "Collect the evidence referenced in the validation report before rerunning validation.".to_string(),
                },
                ValidationRemediationActionV1 {
                    action_id: "resolve-incomplete-classification-or-surface".to_string(),
                    summary: "Resolve the incomplete host classification or required extension surface before treating the result as conclusive.".to_string(),
                },
            ],
        },
        Reason::ValidationBlocked => ValidationRemediationHintV1 {
            hint_id: "unblock-validation-inputs".to_string(),
            reason_code: report.primary_reason_code,
            summary: "Resolve the blocked validation input or activation condition before treating the result as admissible.".to_string(),
            actions: vec![
                ValidationRemediationActionV1 {
                    action_id: "inspect-blocked-inputs".to_string(),
                    summary: "Inspect the warnings, evidence refs, and failed requirements that explain why validation was blocked.".to_string(),
                },
                ValidationRemediationActionV1 {
                    action_id: "satisfy-activation-preconditions".to_string(),
                    summary: "Enable the required activation inputs only if policy allows them and the missing surface is intentional.".to_string(),
                },
            ],
        },
    };

    vec![hint]
}

fn apply_extension_requirements_gate(
    mut base: ValidationReportPayloadV1,
    contract: &HostContractV1,
    contract_payload: &HostContractPayloadV1,
    service_profile: &ServiceProfileV1,
) -> ValidationReportPayloadV1 {
    if !matches!(
        base.verdict,
        ValidationVerdictV1::Fit | ValidationVerdictV1::FitWithDegradation
    ) || service_profile.profile.extension_requirements.is_empty()
    {
        return base;
    }

    let enabled_namespaces = contract
        .contract_basis
        .extension_basis
        .as_ref()
        .map(|basis| {
            basis
                .enabled_extension_namespaces
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();

    let mut namespaces = service_profile
        .profile
        .extension_requirements
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    namespaces.sort();

    let mut blocked_namespaces = Vec::new();
    let mut incomplete_namespaces = Vec::new();
    let mut unevaluated_namespaces = Vec::new();
    let mut registry_error_namespaces = Vec::new();
    let mut unsatisfied_extensions = Vec::new();
    let mut satisfied_extensions = Vec::new();

    for namespace in namespaces {
        if !enabled_namespaces.contains(&namespace) {
            blocked_namespaces.push(namespace);
        } else if !contract_payload.extension_contract.contains_key(&namespace) {
            incomplete_namespaces.push(namespace);
        } else {
            let contract_value = contract_payload
                .extension_contract
                .get(&namespace)
                .expect("checked above");
            let requirement_value = service_profile
                .profile
                .extension_requirements
                .get(&namespace)
                .expect("checked above");
            match evaluate_registered_extension_requirement_v1(
                &namespace,
                contract_value,
                requirement_value,
            ) {
                Ok(Some(ExtensionRequirementEvaluationOutcomeV1::Satisfied)) => {
                    satisfied_extensions.push(namespace);
                }
                Ok(Some(ExtensionRequirementEvaluationOutcomeV1::Unsatisfied { summary })) => {
                    unsatisfied_extensions.push((namespace, summary));
                }
                Ok(None) => unevaluated_namespaces.push(namespace),
                Err(error) => match error.kind {
                    ExtensionEvaluatorRegistryErrorKindV1::RegistryInvalid => {
                        registry_error_namespaces.push((namespace, error.message));
                    }
                    ExtensionEvaluatorRegistryErrorKindV1::ExtensionPayloadInvalid => {
                        incomplete_namespaces.push(namespace);
                    }
                },
            }
        }
    }

    if blocked_namespaces.is_empty()
        && incomplete_namespaces.is_empty()
        && unsatisfied_extensions.is_empty()
        && registry_error_namespaces.is_empty()
        && unevaluated_namespaces.is_empty()
    {
        base.matched_requirements.extend(
            satisfied_extensions
                .iter()
                .map(|namespace| format!("extension_requirements.{namespace}")),
        );
        base.matched_requirements.sort();
        base.matched_requirements.dedup();
        return base;
    }

    let (reason_code, summary, warning, evidence_refs, failed_requirements) = if !blocked_namespaces
        .is_empty()
    {
        let first = blocked_namespaces.first().expect("checked above");
        (
            ValidationReasonCodeV1::ValidationBlocked,
            format!(
                "extension namespace {first} is required by the service profile but not enabled for this contract"
            ),
            Some(
                "extension requirements remain opt-in and fail closed until the namespace is explicitly activated"
                    .to_string(),
            ),
            vec!["$.contract_basis.extension_basis.enabled_extension_namespaces".to_string()],
            blocked_namespaces
                .iter()
                .map(|namespace| format!("extension_requirements.{namespace}"))
                .collect::<Vec<_>>(),
        )
    } else if !registry_error_namespaces.is_empty() {
        let (first, first_summary) = registry_error_namespaces.first().expect("checked above");
        (
            ValidationReasonCodeV1::ValidationBlocked,
            first_summary.to_string(),
            Some(
                "extension evaluator registration must stay unique and typed before enabled namespaces can be evaluated"
                    .to_string(),
            ),
            vec![format!("$.contract.extension_contract.{first}")],
            registry_error_namespaces
                .iter()
                .map(|(namespace, _)| format!("extension_requirements.{namespace}"))
                .collect::<Vec<_>>(),
        )
    } else if !incomplete_namespaces.is_empty() {
        let first = incomplete_namespaces.first().expect("checked above");
        (
            ValidationReasonCodeV1::EvidenceIncomplete,
            format!(
                "extension namespace {first} is enabled but no extension contract content is present"
            ),
            Some(
                "enabled extensions must emit explicit namespaced contract content before their requirements can be evaluated"
                    .to_string(),
            ),
            incomplete_namespaces
                .iter()
                .map(|namespace| format!("$.contract.extension_contract.{namespace}"))
                .collect::<Vec<_>>(),
            incomplete_namespaces
                .iter()
                .map(|namespace| format!("extension_requirements.{namespace}"))
                .collect::<Vec<_>>(),
        )
    } else if !unsatisfied_extensions.is_empty() {
        let (first, first_summary) = unsatisfied_extensions.first().expect("checked above");
        (
            ValidationReasonCodeV1::RequirementUnsatisfied,
            first_summary.to_string(),
            Option::<String>::None,
            vec![format!("$.contract.extension_contract.{first}")],
            unsatisfied_extensions
                .iter()
                .map(|(namespace, _)| format!("extension_requirements.{namespace}"))
                .collect::<Vec<_>>(),
        )
    } else {
        let first = unevaluated_namespaces.first().expect("checked above");
        (
            ValidationReasonCodeV1::ValidationBlocked,
            format!(
                "extension namespace {first} is enabled but no registered extension evaluator is implemented yet"
            ),
            Some(
                "extension content remains append-only until a typed namespace evaluator is registered"
                    .to_string(),
            ),
            unevaluated_namespaces
                .iter()
                .map(|namespace| format!("$.contract.extension_contract.{namespace}"))
                .collect::<Vec<_>>(),
            unevaluated_namespaces
                .iter()
                .map(|namespace| format!("extension_requirements.{namespace}"))
                .collect::<Vec<_>>(),
        )
    };

    for evidence_ref in evidence_refs {
        if !base.evidence_refs.contains(&evidence_ref) {
            base.evidence_refs.push(evidence_ref);
        }
    }

    if let Some(warning) = warning {
        if !base.warnings.contains(&warning) {
            base.warnings.push(warning);
        }
    }

    base.verdict = ValidationVerdictV1::Indeterminate;
    if matches!(reason_code, ValidationReasonCodeV1::RequirementUnsatisfied) {
        base.verdict = ValidationVerdictV1::Unfit;
    }
    base.primary_reason_code = reason_code;
    base.failed_requirements.extend(failed_requirements);
    base.failed_requirements.sort();
    base.failed_requirements.dedup();
    base.selected_degradation_tier = None;
    base.summary = summary;
    if matches!(reason_code, ValidationReasonCodeV1::RequirementUnsatisfied) {
        if let Some((namespace, _)) = unsatisfied_extensions.first() {
            if namespace == CUDA_RUNTIME_NAMESPACE {
                if let Some(requirement_value) = service_profile
                    .profile
                    .extension_requirements
                    .get(CUDA_RUNTIME_NAMESPACE)
                {
                    if let Ok(requirement) =
                        decode_cuda_runtime_requirement_from_value(requirement_value)
                    {
                        if requirement.minimum_allocatable_memory_bytes.is_some()
                            || service_profile
                                .profile
                                .core_requirements
                                .min_policy_scoped_accelerators
                                .is_some()
                        {
                            let related_requirements = if base.failed_requirements.is_empty() {
                                vec![cuda_runtime_namespace_requirement_key()]
                            } else {
                                base.failed_requirements.clone()
                            };
                            let evidence_refs = if base.evidence_refs.is_empty() {
                                vec![cuda_runtime_contract_evidence_ref()]
                            } else {
                                base.evidence_refs.clone()
                            };
                            attach_cuda_runtime_validation_diagnostic(
                                &mut base,
                                CudaRuntimeValidationDiagnosticSelector {
                                    detail_code: CudaRuntimeValidationDetailCodeV1::StaticRequirementUnsatisfied,
                                    checkpoint: CudaRuntimeValidationCheckpointV1::RuntimeExtensionGate,
                                },
                                related_requirements,
                                evidence_refs,
                                CudaRuntimeValidationDiagnosticPayload {
                                    required_allocatable_memory_bytes: requirement
                                        .minimum_allocatable_memory_bytes,
                                    observed_allocatable_memory_bytes: None,
                                    observed_total_memory_bytes: None,
                                    required_qualifying_device_count: service_profile
                                        .profile
                                        .core_requirements
                                        .min_policy_scoped_accelerators,
                                    observed_qualifying_device_count: None,
                                    required_device_allocatable_memory_bytes: requirement
                                        .minimum_device_allocatable_memory_bytes,
                                    required_qualifying_device_aggregate_allocatable_memory_bytes:
                                        requirement
                                            .minimum_qualifying_device_aggregate_allocatable_memory_bytes,
                                    observed_qualifying_device_aggregate_allocatable_memory_bytes:
                                        None,
                                },
                            );
                        }
                    }
                }
            }
        }
    }
    base
}

fn apply_runtime_extension_state_gate(
    mut base: ValidationReportPayloadV1,
    service_profile: &ServiceProfileV1,
    host_state: Option<&HostStateV1>,
    mode: ValidationModeV1,
    max_state_age_seconds: Option<u64>,
    validated_at: &str,
) -> ValidationReportPayloadV1 {
    if !matches!(
        base.verdict,
        ValidationVerdictV1::Fit | ValidationVerdictV1::FitWithDegradation
    ) {
        return base;
    }

    let Some(requirement_value) = service_profile
        .profile
        .extension_requirements
        .get(CUDA_RUNTIME_NAMESPACE)
    else {
        return base;
    };

    let requirement = match decode_cuda_runtime_requirement_from_value(requirement_value) {
        Ok(requirement) => requirement,
        Err(error) => {
            return runtime_extension_validation_blocked_report(
                base,
                vec![cuda_runtime_namespace_requirement_key()],
                vec![format!("$.state.extension_state.{CUDA_RUNTIME_NAMESPACE}")],
                error.message,
            );
        }
    };

    let required_qualifying_device_count = service_profile
        .profile
        .core_requirements
        .min_policy_scoped_accelerators;
    let required_allocatable_memory_bytes = requirement.minimum_allocatable_memory_bytes;
    let required_device_allocatable_memory_bytes =
        requirement.minimum_device_allocatable_memory_bytes;
    let required_qualifying_device_aggregate_allocatable_memory_bytes =
        requirement.minimum_qualifying_device_aggregate_allocatable_memory_bytes;

    if required_qualifying_device_count.is_none()
        && required_allocatable_memory_bytes.is_none()
        && required_qualifying_device_aggregate_allocatable_memory_bytes.is_none()
    {
        return base;
    }

    let requirement_keys = cuda_runtime_requirement_keys(
        required_qualifying_device_count,
        required_allocatable_memory_bytes,
        required_device_allocatable_memory_bytes,
        required_qualifying_device_aggregate_allocatable_memory_bytes,
    );
    let evidence_refs = cuda_runtime_gate_evidence_refs(
        required_qualifying_device_count,
        required_allocatable_memory_bytes,
        required_device_allocatable_memory_bytes,
        required_qualifying_device_aggregate_allocatable_memory_bytes,
    );
    let threshold_label = cuda_runtime_threshold_label(
        required_qualifying_device_count,
        required_allocatable_memory_bytes,
        required_device_allocatable_memory_bytes,
        required_qualifying_device_aggregate_allocatable_memory_bytes,
    );
    let diagnostic_payload = CudaRuntimeValidationDiagnosticPayload {
        required_allocatable_memory_bytes,
        observed_allocatable_memory_bytes: None,
        observed_total_memory_bytes: None,
        required_qualifying_device_count,
        observed_qualifying_device_count: None,
        required_device_allocatable_memory_bytes,
        required_qualifying_device_aggregate_allocatable_memory_bytes,
        observed_qualifying_device_aggregate_allocatable_memory_bytes: None,
    };

    if matches!(mode, ValidationModeV1::ContractOnly) {
        return runtime_extension_state_missing_or_stale_report(
            base,
            requirement_keys,
            evidence_refs,
            ValidationReasonCodeV1::StateMissing,
            &format!("contract-only validation requires host-state.v2 for {threshold_label}"),
            CudaRuntimeValidationDiagnosticSelector {
                detail_code: CudaRuntimeValidationDetailCodeV1::RuntimeStateMissing,
                checkpoint: CudaRuntimeValidationCheckpointV1::RuntimeExtensionState,
            },
            diagnostic_payload,
        );
    }

    let Some(host_state) = host_state else {
        return runtime_extension_state_missing_or_stale_report(
            base,
            requirement_keys,
            evidence_refs,
            ValidationReasonCodeV1::StateMissing,
            &format!("host-state is required for {threshold_label}"),
            CudaRuntimeValidationDiagnosticSelector {
                detail_code: CudaRuntimeValidationDetailCodeV1::RuntimeStateMissing,
                checkpoint: CudaRuntimeValidationCheckpointV1::RuntimeExtensionState,
            },
            diagnostic_payload,
        );
    };

    match is_state_stale(host_state, max_state_age_seconds, validated_at) {
        Ok(true) => {
            let summary = match mode {
                ValidationModeV1::StateAdvisory => {
                    format!("stale host-state remains explicit for {threshold_label}")
                }
                _ => format!("stale host-state blocks {threshold_label}"),
            };
            return runtime_extension_state_missing_or_stale_report(
                base,
                requirement_keys,
                cuda_runtime_evidence_refs_with_freshness(evidence_refs),
                ValidationReasonCodeV1::StateStale,
                &summary,
                CudaRuntimeValidationDiagnosticSelector {
                    detail_code: CudaRuntimeValidationDetailCodeV1::RuntimeStateStale,
                    checkpoint: CudaRuntimeValidationCheckpointV1::RuntimeExtensionFreshness,
                },
                diagnostic_payload,
            );
        }
        Ok(false) => {}
        Err(message) => return freshness_parse_failed_report(message),
    }

    let Some(state_value) = host_state.state.extension_state.get(CUDA_RUNTIME_NAMESPACE) else {
        return runtime_extension_state_missing_or_stale_report(
            base,
            requirement_keys,
            evidence_refs,
            ValidationReasonCodeV1::StateMissing,
            &format!(
                "host-state does not include CUDA runtime extension state required for {threshold_label}"
            ),
            CudaRuntimeValidationDiagnosticSelector {
                detail_code: CudaRuntimeValidationDetailCodeV1::RuntimeStateMissing,
                checkpoint: CudaRuntimeValidationCheckpointV1::RuntimeExtensionState,
            },
            diagnostic_payload,
        );
    };
    let state = match decode_cuda_runtime_state_from_value(state_value) {
        Ok(state) => state,
        Err(error) => {
            return runtime_extension_validation_blocked_report(
                base,
                requirement_keys,
                evidence_refs,
                error.message,
            );
        }
    };

    if !matches!(
        state.runtime_state,
        ObservationStateV1::Observed | ObservationStateV1::PartiallyObserved
    ) {
        let summary = if required_qualifying_device_count.is_some() {
            format!("{threshold_label} are missing or unknown in host-state")
        } else {
            "CUDA allocatable memory is missing or unknown in host-state".to_string()
        };
        return runtime_extension_state_missing_or_stale_report(
            base,
            requirement_keys,
            evidence_refs,
            ValidationReasonCodeV1::StateMissing,
            &summary,
            CudaRuntimeValidationDiagnosticSelector {
                detail_code: CudaRuntimeValidationDetailCodeV1::RuntimeStateMissing,
                checkpoint: CudaRuntimeValidationCheckpointV1::RuntimeExtensionState,
            },
            diagnostic_payload,
        );
    }

    let allocatable_memory_bytes = required_allocatable_memory_bytes.map(|_| {
        match (
            &state.allocatable_memory_bytes.state,
            &state.allocatable_memory_bytes.value,
        ) {
            (ObservationStateV1::Observed, Some(value))
            | (ObservationStateV1::PartiallyObserved, Some(value)) => Ok(*value),
            _ => Err(()),
        }
    });
    let allocatable_memory_bytes = match allocatable_memory_bytes.transpose() {
        Ok(value) => value,
        Err(()) => {
            return runtime_extension_state_missing_or_stale_report(
                base,
                requirement_keys,
                evidence_refs,
                ValidationReasonCodeV1::StateMissing,
                "CUDA allocatable memory is missing or unknown in host-state",
                CudaRuntimeValidationDiagnosticSelector {
                    detail_code: CudaRuntimeValidationDetailCodeV1::RuntimeStateMissing,
                    checkpoint: CudaRuntimeValidationCheckpointV1::RuntimeExtensionState,
                },
                diagnostic_payload,
            );
        }
    };

    let observed_qualifying_device_count = (required_qualifying_device_count.is_some()
        || required_qualifying_device_aggregate_allocatable_memory_bytes.is_some())
    .then(|| {
        cuda_runtime_qualifying_device_count(&state, required_device_allocatable_memory_bytes)
    });

    if let (Some(required_count), Some(observed_count)) = (
        required_qualifying_device_count,
        observed_qualifying_device_count,
    ) {
        if observed_count < required_count {
            let threshold_summary = match required_device_allocatable_memory_bytes {
                Some(minimum_device_allocatable_memory_bytes) => format!(
                    "CUDA qualifying device count {} is below the required minimum {} at per-device floor {}",
                    observed_count,
                    required_count,
                    format_bytes(minimum_device_allocatable_memory_bytes)
                ),
                None => format!(
                    "CUDA qualifying device count {} is below the required minimum {}",
                    observed_count, required_count
                ),
            };
            return runtime_extension_threshold_unsatisfied_report(
                base,
                requirement_keys,
                evidence_refs,
                threshold_summary,
                CudaRuntimeValidationDiagnosticSelector {
                    detail_code:
                        CudaRuntimeValidationDetailCodeV1::QualifyingDeviceCountInsufficient,
                    checkpoint: CudaRuntimeValidationCheckpointV1::RuntimeExtensionSummary,
                },
                CudaRuntimeValidationDiagnosticPayload {
                    required_allocatable_memory_bytes: None,
                    observed_allocatable_memory_bytes: None,
                    observed_total_memory_bytes: None,
                    required_qualifying_device_count: Some(required_count),
                    observed_qualifying_device_count: Some(observed_count),
                    required_device_allocatable_memory_bytes,
                    required_qualifying_device_aggregate_allocatable_memory_bytes: None,
                    observed_qualifying_device_aggregate_allocatable_memory_bytes: None,
                },
            );
        }
    }

    let observed_qualifying_device_aggregate_allocatable_memory_bytes =
        required_qualifying_device_aggregate_allocatable_memory_bytes.map(|_| {
            cuda_runtime_qualifying_device_aggregate_allocatable_memory(
                &state,
                required_device_allocatable_memory_bytes,
            )
        });

    if let (Some(required_aggregate), Some(observed_aggregate)) = (
        required_qualifying_device_aggregate_allocatable_memory_bytes,
        observed_qualifying_device_aggregate_allocatable_memory_bytes,
    ) {
        if observed_aggregate < required_aggregate {
            return runtime_extension_threshold_unsatisfied_report(
                base,
                requirement_keys,
                evidence_refs,
                format!(
                    "CUDA qualifying-device aggregate allocatable memory {} is below the required floor {}",
                    format_bytes(observed_aggregate),
                    format_bytes(required_aggregate)
                ),
                CudaRuntimeValidationDiagnosticSelector {
                    detail_code: CudaRuntimeValidationDetailCodeV1::QualifyingDeviceAggregateAllocatableMemoryInsufficient,
                    checkpoint: CudaRuntimeValidationCheckpointV1::RuntimeExtensionSummary,
                },
                CudaRuntimeValidationDiagnosticPayload {
                    required_allocatable_memory_bytes: None,
                    observed_allocatable_memory_bytes: None,
                    observed_total_memory_bytes: None,
                    required_qualifying_device_count,
                    observed_qualifying_device_count,
                    required_device_allocatable_memory_bytes,
                    required_qualifying_device_aggregate_allocatable_memory_bytes: Some(
                        required_aggregate,
                    ),
                    observed_qualifying_device_aggregate_allocatable_memory_bytes: Some(
                        observed_aggregate,
                    ),
                },
            );
        }
    }

    if let (Some(required_allocatable_memory_bytes), Some(observed_allocatable_memory_bytes)) =
        (required_allocatable_memory_bytes, allocatable_memory_bytes)
    {
        if observed_allocatable_memory_bytes < required_allocatable_memory_bytes {
            return runtime_extension_threshold_unsatisfied_report(
                base,
                requirement_keys,
                evidence_refs,
                format!(
                    "CUDA allocatable memory {} is below the required floor {}",
                    format_bytes(observed_allocatable_memory_bytes),
                    format_bytes(required_allocatable_memory_bytes)
                ),
                CudaRuntimeValidationDiagnosticSelector {
                    detail_code: CudaRuntimeValidationDetailCodeV1::AllocatableMemoryInsufficient,
                    checkpoint: CudaRuntimeValidationCheckpointV1::RuntimeExtensionSummary,
                },
                CudaRuntimeValidationDiagnosticPayload {
                    required_allocatable_memory_bytes: Some(required_allocatable_memory_bytes),
                    observed_allocatable_memory_bytes: Some(observed_allocatable_memory_bytes),
                    observed_total_memory_bytes: cuda_runtime_total_memory_bytes(host_state),
                    required_qualifying_device_count: None,
                    observed_qualifying_device_count: None,
                    required_device_allocatable_memory_bytes: None,
                    required_qualifying_device_aggregate_allocatable_memory_bytes: None,
                    observed_qualifying_device_aggregate_allocatable_memory_bytes: None,
                },
            );
        }
    }

    if let Some(required_allocatable_memory_bytes) = required_allocatable_memory_bytes {
        if let Some(observed_allocatable_memory_bytes) = allocatable_memory_bytes {
            base.matched_requirements
                .push(cuda_runtime_allocatable_requirement_key());
            base.matched_requirements.sort();
            base.matched_requirements.dedup();
            for evidence_ref in cuda_runtime_threshold_evidence_refs() {
                if !base.evidence_refs.contains(&evidence_ref) {
                    base.evidence_refs.push(evidence_ref);
                }
            }
            base.evidence_refs.sort();
            base.evidence_refs.dedup();
            if required_qualifying_device_count.is_none() {
                attach_cuda_runtime_validation_diagnostic(
                    &mut base,
                    CudaRuntimeValidationDiagnosticSelector {
                        detail_code: CudaRuntimeValidationDetailCodeV1::RuntimeThresholdSatisfied,
                        checkpoint: CudaRuntimeValidationCheckpointV1::RuntimeExtensionSummary,
                    },
                    vec![cuda_runtime_allocatable_requirement_key()],
                    cuda_runtime_threshold_evidence_refs(),
                    CudaRuntimeValidationDiagnosticPayload {
                        required_allocatable_memory_bytes: Some(required_allocatable_memory_bytes),
                        observed_allocatable_memory_bytes: Some(observed_allocatable_memory_bytes),
                        observed_total_memory_bytes: cuda_runtime_total_memory_bytes(host_state),
                        required_qualifying_device_count: None,
                        observed_qualifying_device_count: None,
                        required_device_allocatable_memory_bytes: None,
                        required_qualifying_device_aggregate_allocatable_memory_bytes: None,
                        observed_qualifying_device_aggregate_allocatable_memory_bytes: None,
                    },
                );
            }
        }
    }

    if let Some(required_aggregate) = required_qualifying_device_aggregate_allocatable_memory_bytes
    {
        if let Some(observed_aggregate) =
            observed_qualifying_device_aggregate_allocatable_memory_bytes
        {
            base.matched_requirements
                .push(cuda_runtime_qualifying_device_aggregate_allocatable_requirement_key());
            if required_device_allocatable_memory_bytes.is_some() {
                base.matched_requirements
                    .push(cuda_runtime_device_allocatable_requirement_key());
            }
            base.matched_requirements.sort();
            base.matched_requirements.dedup();
            for evidence_ref in evidence_refs.clone() {
                if !base.evidence_refs.contains(&evidence_ref) {
                    base.evidence_refs.push(evidence_ref);
                }
            }
            base.evidence_refs.sort();
            base.evidence_refs.dedup();
            attach_cuda_runtime_validation_diagnostic(
                &mut base,
                CudaRuntimeValidationDiagnosticSelector {
                    detail_code: CudaRuntimeValidationDetailCodeV1::QualifyingDeviceAggregateAllocatableMemoryThresholdSatisfied,
                    checkpoint: CudaRuntimeValidationCheckpointV1::RuntimeExtensionSummary,
                },
                requirement_keys,
                evidence_refs,
                CudaRuntimeValidationDiagnosticPayload {
                    required_allocatable_memory_bytes: None,
                    observed_allocatable_memory_bytes: None,
                    observed_total_memory_bytes: None,
                    required_qualifying_device_count,
                    observed_qualifying_device_count,
                    required_device_allocatable_memory_bytes,
                    required_qualifying_device_aggregate_allocatable_memory_bytes: Some(
                        required_aggregate,
                    ),
                    observed_qualifying_device_aggregate_allocatable_memory_bytes: Some(
                        observed_aggregate,
                    ),
                },
            );
            return base;
        }
    }

    if let Some(observed_qualifying_device_count) = observed_qualifying_device_count {
        if required_device_allocatable_memory_bytes.is_some() {
            base.matched_requirements
                .push(cuda_runtime_device_allocatable_requirement_key());
        }
        base.matched_requirements.sort();
        base.matched_requirements.dedup();
        for evidence_ref in evidence_refs.clone() {
            if !base.evidence_refs.contains(&evidence_ref) {
                base.evidence_refs.push(evidence_ref);
            }
        }
        base.evidence_refs.sort();
        base.evidence_refs.dedup();
        attach_cuda_runtime_validation_diagnostic(
            &mut base,
            CudaRuntimeValidationDiagnosticSelector {
                detail_code: CudaRuntimeValidationDetailCodeV1::QualifyingDeviceThresholdSatisfied,
                checkpoint: CudaRuntimeValidationCheckpointV1::RuntimeExtensionSummary,
            },
            requirement_keys,
            evidence_refs,
            CudaRuntimeValidationDiagnosticPayload {
                required_allocatable_memory_bytes: None,
                observed_allocatable_memory_bytes: None,
                observed_total_memory_bytes: None,
                required_qualifying_device_count,
                observed_qualifying_device_count: Some(observed_qualifying_device_count),
                required_device_allocatable_memory_bytes,
                required_qualifying_device_aggregate_allocatable_memory_bytes: None,
                observed_qualifying_device_aggregate_allocatable_memory_bytes: None,
            },
        );
        return base;
    }
    base
}

pub fn load_contract_artifact_for_validation(
    path: &Path,
) -> Result<HostContractV1, ValidationError> {
    load_host_contract_artifact_from_path(path).map_err(|error| {
        ValidationError::new(
            ValidationErrorCode::ContractArtifactInvalid,
            "contract_load",
            error.message,
        )
    })
}

pub fn load_service_profile_artifact_for_validation(
    path: &Path,
) -> Result<ServiceProfileV1, ValidationError> {
    load_service_profile_from_path(path).map_err(|error| {
        ValidationError::new(
            ValidationErrorCode::ServiceProfileArtifactInvalid,
            "service_profile_load",
            error.message,
        )
    })
}

pub fn load_host_state_artifact_for_validation(
    path: &Path,
) -> Result<HostStateV1, ValidationError> {
    load_host_state_from_path(path).map_err(|error| {
        ValidationError::new(
            ValidationErrorCode::StateArtifactInvalid,
            "state_load",
            error.message,
        )
    })
}

pub fn load_validation_report_from_path(
    path: &Path,
) -> Result<ValidationReportV1, ValidationError> {
    let text = fs::read_to_string(path).map_err(|error| {
        ValidationError::new(
            ValidationErrorCode::ValidationInputInvalid,
            "validation_report_emit",
            format!(
                "failed to read validation report {}: {error}",
                path.display()
            ),
        )
    })?;
    let report: ValidationReportV1 = serde_json::from_str(&text).map_err(|error| {
        ValidationError::new(
            ValidationErrorCode::ValidationInputInvalid,
            "validation_report_emit",
            format!(
                "failed to decode validation report {}: {error}",
                path.display()
            ),
        )
    })?;

    validate_validation_report(&report).map_err(|error| {
        ValidationError::new(
            ValidationErrorCode::ValidationReportInvalid,
            "validation_report_emit",
            error.message,
        )
    })?;

    Ok(report)
}

fn evaluate_contract_only(
    contract: &HostContractPayloadV1,
    service_profile: &ServiceProfileV1,
) -> ValidationReportPayloadV1 {
    // Contract-only validation is restricted to static contract claims. Runtime allocatable
    // thresholds stay explicitly indeterminate until a host-state artifact is supplied.
    let matched_requirements = match evaluate_visibility_scope_gate(contract, service_profile) {
        Ok(matched_requirements) => matched_requirements,
        Err(report) => return *report,
    };
    let profile = &service_profile.profile;

    if profile
        .core_requirements
        .min_allocatable_cpu_logical_cores
        .is_some()
        || profile
            .core_requirements
            .min_allocatable_memory_bytes
            .is_some()
    {
        let mut failed_requirements = Vec::new();
        if profile
            .core_requirements
            .min_allocatable_cpu_logical_cores
            .is_some()
        {
            failed_requirements
                .push("core_requirements.min_allocatable_cpu_logical_cores".to_string());
        }
        if profile
            .core_requirements
            .min_allocatable_memory_bytes
            .is_some()
        {
            failed_requirements.push("core_requirements.min_allocatable_memory_bytes".to_string());
        }
        return ValidationReportPayloadV1 {
            verdict: ValidationVerdictV1::Indeterminate,
            primary_reason_code: ValidationReasonCodeV1::StateMissing,
            matched_requirements,
            failed_requirements,
            evidence_refs: vec![],
            policy_refs: vec![],
            assurance_mismatches: vec![],
            selected_degradation_tier: None,
            warnings: vec![
                "contract_only validation cannot satisfy allocatable runtime thresholds without host-state.v2".to_string(),
            ],
            summary: "contract-only validation requires host-state.v2 for allocatable thresholds"
                .to_string(),
            ..ValidationReportPayloadV1::default()
        };
    }

    evaluate_static_requirements(contract, service_profile, matched_requirements)
}

fn evaluate_state_mode(
    contract: &HostContractPayloadV1,
    service_profile: &ServiceProfileV1,
    host_state: &HostStateV1,
    mode: ValidationModeV1,
    max_state_age_seconds: Option<u64>,
    validated_at: &str,
) -> ValidationReportPayloadV1 {
    evaluate_with_optional_state(
        contract,
        service_profile,
        Some(host_state),
        mode,
        max_state_age_seconds,
        validated_at,
    )
}

fn evaluate_with_optional_state(
    contract: &HostContractPayloadV1,
    service_profile: &ServiceProfileV1,
    host_state: Option<&HostStateV1>,
    mode: ValidationModeV1,
    max_state_age_seconds: Option<u64>,
    validated_at: &str,
) -> ValidationReportPayloadV1 {
    // State-aware validation only runs after the static contract path has already produced a fit
    // or degraded fit. Runtime state can narrow that result, but it never rescues a statically
    // incompatible host.
    let matched_requirements = match evaluate_visibility_scope_gate(contract, service_profile) {
        Ok(matched_requirements) => matched_requirements,
        Err(report) => return *report,
    };
    let mut report = evaluate_static_requirements(contract, service_profile, matched_requirements);
    let profile = &service_profile.profile;

    if !runtime_thresholds_declared(service_profile) {
        if host_state.is_some_and(|state| {
            matches!(
                is_state_stale(state, max_state_age_seconds, validated_at),
                Ok(true)
            )
        }) {
            report.warnings.push(
                "host-state snapshot is stale but no runtime-facing thresholds depend on it"
                    .to_string(),
            );
        }
        return report;
    }

    if !matches!(
        report.verdict,
        ValidationVerdictV1::Fit | ValidationVerdictV1::FitWithDegradation
    ) {
        return report;
    }

    let Some(host_state) = host_state else {
        return runtime_state_missing_or_stale_report(
            report,
            service_profile,
            ValidationReasonCodeV1::StateMissing,
            "host-state is required for runtime-threshold evaluation",
        );
    };

    match is_state_stale(host_state, max_state_age_seconds, validated_at) {
        Ok(true) => {
            return runtime_state_missing_or_stale_report(
                report,
                service_profile,
                ValidationReasonCodeV1::StateStale,
                match mode {
                    ValidationModeV1::StateAdvisory => {
                        "stale host-state remains explicit in state_advisory validation"
                    }
                    _ => "stale host-state blocks runtime-threshold evaluation",
                },
            );
        }
        Ok(false) => {}
        Err(message) => return freshness_parse_failed_report(message),
    }

    if let Some(runtime_topology_report) =
        evaluate_runtime_topology_requirements(service_profile, host_state, &report)
    {
        return runtime_topology_report;
    }

    if let Some(degraded_report) =
        evaluate_runtime_operability(service_profile, host_state, report.clone())
    {
        return degraded_report;
    }

    let mut matched_requirements = report.matched_requirements.clone();
    let mut failed_requirements = Vec::new();

    if let Some(min_cpu) = profile.core_requirements.min_allocatable_cpu_logical_cores {
        match scalar_state_value(
            &host_state
                .state
                .core_state
                .resources
                .allocatable_cpu_logical_cores,
            "core_requirements.min_allocatable_cpu_logical_cores",
        ) {
            Ok(value) => {
                if value < min_cpu {
                    return runtime_threshold_unsatisfied_report(
                        report,
                        vec!["core_requirements.min_allocatable_cpu_logical_cores".to_string()],
                        format!(
                            "allocatable CPU logical cores {} are below the required floor {}",
                            value, min_cpu
                        ),
                    );
                }
                matched_requirements
                    .push("core_requirements.min_allocatable_cpu_logical_cores".to_string());
            }
            Err(report_payload) => return runtime_missing_report(report, *report_payload),
        }
    }

    if let Some(min_memory) = profile.core_requirements.min_allocatable_memory_bytes {
        match scalar_state_value(
            &host_state
                .state
                .core_state
                .resources
                .allocatable_memory_bytes,
            "core_requirements.min_allocatable_memory_bytes",
        ) {
            Ok(value) => {
                if value < min_memory {
                    failed_requirements
                        .push("core_requirements.min_allocatable_memory_bytes".to_string());
                    return runtime_threshold_unsatisfied_report(
                        report,
                        failed_requirements,
                        format!(
                            "allocatable memory {} is below the required floor {}",
                            value, min_memory
                        ),
                    );
                }
                matched_requirements
                    .push("core_requirements.min_allocatable_memory_bytes".to_string());
            }
            Err(report_payload) => return runtime_missing_report(report, *report_payload),
        }
    }

    report.matched_requirements = matched_requirements;
    report.evidence_refs.extend(runtime_evidence_refs());
    report.evidence_refs.sort();
    report.evidence_refs.dedup();
    report
}

fn evaluate_visibility_scope_gate(
    contract: &HostContractPayloadV1,
    service_profile: &ServiceProfileV1,
) -> Result<Vec<String>, Box<ValidationReportPayloadV1>> {
    // Visibility scope is a hard gate because it constrains what deployment context the contract
    // is allowed to represent at all. If this fails, later capability checks do not run.
    let profile = &service_profile.profile;
    let visibility_scope = &contract
        .core_contract
        .execution_constraints
        .visibility_scope;

    if profile
        .core_requirements
        .allowed_visibility_scopes
        .contains(visibility_scope)
    {
        return Ok(vec![
            "core_requirements.allowed_visibility_scopes".to_string()
        ]);
    }

    let allowed_scopes = profile
        .core_requirements
        .allowed_visibility_scopes
        .iter()
        .map(visibility_scope_label)
        .collect::<Vec<_>>()
        .join(", ");

    let (verdict, primary_reason_code, warnings, summary) = match visibility_scope {
        VisibilityScopeV1::Unknown => (
            ValidationVerdictV1::Indeterminate,
            ValidationReasonCodeV1::EvidenceIncomplete,
            vec![
                "execution context remained unresolved during survey; visibility allowlist could not be satisfied conclusively"
                    .to_string(),
            ],
            format!(
                "contract visibility scope is unknown; service-profile only allows {allowed_scopes}"
            ),
        ),
        _ => (
            ValidationVerdictV1::Unfit,
            ValidationReasonCodeV1::RequirementUnsatisfied,
            vec![],
            format!(
                "contract visibility scope {} is outside the service-profile allowlist {}",
                visibility_scope_label(visibility_scope),
                allowed_scopes
            ),
        ),
    };

    Err(Box::new(ValidationReportPayloadV1 {
        verdict,
        primary_reason_code,
        matched_requirements: vec![],
        failed_requirements: vec!["core_requirements.allowed_visibility_scopes".to_string()],
        evidence_refs: vec!["$.contract.execution_constraints.visibility_scope".to_string()],
        policy_refs: vec![],
        assurance_mismatches: vec![],
        selected_degradation_tier: None,
        warnings,
        summary,
        ..ValidationReportPayloadV1::default()
    }))
}

fn visibility_scope_label(scope: &VisibilityScopeV1) -> &'static str {
    match scope {
        VisibilityScopeV1::BareMetalLike => "bare_metal_like",
        VisibilityScopeV1::VmLike => "vm_like",
        VisibilityScopeV1::ContainerRestricted => "container_restricted",
        VisibilityScopeV1::Unknown => "unknown",
    }
}

fn runtime_state_missing_or_stale_report(
    report: ValidationReportPayloadV1,
    service_profile: &ServiceProfileV1,
    reason_code: ValidationReasonCodeV1,
    summary: &str,
) -> ValidationReportPayloadV1 {
    let mut warnings = report.warnings;
    warnings.push(summary.to_string());
    ValidationReportPayloadV1 {
        verdict: ValidationVerdictV1::Indeterminate,
        primary_reason_code: reason_code,
        matched_requirements: report.matched_requirements,
        failed_requirements: runtime_requirement_keys(service_profile),
        evidence_refs: runtime_evidence_refs(),
        policy_refs: report.policy_refs,
        assurance_mismatches: report.assurance_mismatches,
        selected_degradation_tier: None,
        warnings,
        summary: summary.to_string(),
        ..ValidationReportPayloadV1::default()
    }
}

fn is_state_stale(
    host_state: &HostStateV1,
    max_state_age_seconds: Option<u64>,
    validated_at: &str,
) -> Result<bool, &'static str> {
    if host_state.state.core_state.freshness.freshness_state == FreshnessStateV1::Stale {
        return Ok(true);
    }

    let Some(max_state_age_seconds) = max_state_age_seconds else {
        return Ok(false);
    };
    let validated_at_seconds = parse_timestamp_seconds(validated_at)
        .ok_or("validation timestamp must be unix:<seconds> or UTC RFC3339")?;
    let observed_at_seconds =
        parse_timestamp_seconds(&host_state.state.core_state.freshness.observed_at)
            .ok_or("state freshness timestamp must be unix:<seconds> or UTC RFC3339")?;

    Ok(validated_at_seconds.saturating_sub(observed_at_seconds) > max_state_age_seconds)
}

fn freshness_parse_failed_report(message: &'static str) -> ValidationReportPayloadV1 {
    ValidationReportPayloadV1 {
        verdict: ValidationVerdictV1::Indeterminate,
        primary_reason_code: ValidationReasonCodeV1::ValidationBlocked,
        matched_requirements: vec![],
        failed_requirements: vec![],
        evidence_refs: vec![],
        policy_refs: vec![],
        assurance_mismatches: vec![],
        selected_degradation_tier: None,
        warnings: vec![message.to_string()],
        summary: message.to_string(),
        ..ValidationReportPayloadV1::default()
    }
}

fn parse_timestamp_seconds(value: &str) -> Option<u64> {
    if let Some(rest) = value.strip_prefix("unix:") {
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
    if !(1..=12).contains(&month) || day == 0 || day > 31 {
        return None;
    }

    let adjusted_year = year - if month <= 2 { 1 } else { 0 };
    let era = if adjusted_year >= 0 {
        adjusted_year / 400
    } else {
        (adjusted_year - 399) / 400
    };
    let yoe = adjusted_year - era * 400;
    let month_index = month as i32;
    let doy = (153 * (month_index + if month_index > 2 { -3 } else { 9 }) + 2) / 5 + day as i32 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;

    (days >= 0).then_some(days as u64)
}

fn evaluate_static_requirements(
    contract: &HostContractPayloadV1,
    service_profile: &ServiceProfileV1,
    mut matched_requirements: Vec<String>,
) -> ValidationReportPayloadV1 {
    // The static path is ordered: unresolved assurance predicates first, then full-contract
    // exclusions, then primary capability, then primary-capability assurance, then the shared
    // static hard-requirement bundle, and finally degradation tiers in declared order if the
    // primary capability path is unavailable. Degradation candidates do not get to skip the
    // shared hard gates.
    let profile = &service_profile.profile;

    if !profile.assurance_predicates.is_empty() {
        matched_requirements.push("core_requirements.primary_capability_class".to_string());
        return ValidationReportPayloadV1 {
            verdict: ValidationVerdictV1::Indeterminate,
            primary_reason_code: ValidationReasonCodeV1::AssurancePredicateUnresolved,
            matched_requirements,
            failed_requirements: vec!["assurance_predicates".to_string()],
            evidence_refs: vec![],
            policy_refs: vec![],
            assurance_mismatches: profile
                .assurance_predicates
                .iter()
                .map(|predicate| predicate_label(*predicate).to_string())
                .collect(),
            selected_degradation_tier: None,
            warnings: vec![
                "validation cannot resolve assurance predicates from the current baseline"
                    .to_string(),
            ],
            summary: "assurance predicates remain unresolved".to_string(),
            ..ValidationReportPayloadV1::default()
        };
    }

    let forbidden_capabilities = collect_forbidden_contract_capabilities(contract, profile);
    if !forbidden_capabilities.is_empty() {
        let mut evidence_refs = forbidden_capabilities
            .iter()
            .flat_map(|(_, claim)| claim.evidence_refs.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let mut policy_refs = forbidden_capabilities
            .iter()
            .flat_map(|(_, claim)| claim.rule_ids.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        evidence_refs.sort();
        policy_refs.sort();

        let forbidden_labels = forbidden_capabilities
            .iter()
            .map(|(capability_class, _)| (*capability_class).to_string())
            .collect::<Vec<_>>();
        let summary = match forbidden_labels.as_slice() {
            [single] => format!(
                "service profile forbids capability class {single}, but the host contract exposes it"
            ),
            _ => format!(
                "service profile forbids capability classes {}, but the host contract exposes them",
                forbidden_labels.join(", ")
            ),
        };

        return ValidationReportPayloadV1 {
            verdict: ValidationVerdictV1::Unfit,
            primary_reason_code: ValidationReasonCodeV1::RequirementUnsatisfied,
            matched_requirements,
            failed_requirements: vec!["exclusions.forbidden_capability_classes".to_string()],
            evidence_refs,
            policy_refs,
            assurance_mismatches: vec![],
            selected_degradation_tier: None,
            warnings: vec![],
            summary,
            ..ValidationReportPayloadV1::default()
        };
    }

    let primary_capability = &profile.core_requirements.primary_capability_class;
    let primary_match = resolve_capability_match(contract, primary_capability);
    if let Some(primary_match) = primary_match {
        if primary_match.claim.admissible && !is_forbidden(profile, primary_capability) {
            matched_requirements.push("core_requirements.primary_capability_class".to_string());
            if let Some(report) = evaluate_explicit_assurance_requirements(
                service_profile,
                primary_match.claim,
                matched_requirements.clone(),
            ) {
                return report;
            }
            if let Some(report) = evaluate_contract_shared_static_requirements(
                contract,
                service_profile,
                matched_requirements.clone(),
            ) {
                return report;
            }
            if profile
                .core_requirements
                .min_policy_scoped_accelerators
                .is_some()
            {
                matched_requirements
                    .push("core_requirements.min_policy_scoped_accelerators".to_string());
            }
            return ValidationReportPayloadV1 {
                verdict: ValidationVerdictV1::Fit,
                primary_reason_code: ValidationReasonCodeV1::RequirementsSatisfied,
                matched_requirements,
                failed_requirements: vec![],
                evidence_refs: primary_match.claim.evidence_refs.clone(),
                policy_refs: primary_match.claim.rule_ids.clone(),
                assurance_mismatches: vec![],
                selected_degradation_tier: None,
                warnings: vec![],
                summary: requirements_satisfied_summary(
                    primary_capability,
                    primary_match.matched_capability_class,
                ),
                ..ValidationReportPayloadV1::default()
            };
        }

        if let Some((tier_id, fallback_match)) = select_degradation_tier(contract, service_profile)
        {
            let mut matched_requirements = vec![
                "core_requirements.allowed_visibility_scopes".to_string(),
                format!("degradation_ladder.{tier_id}"),
            ];
            if profile
                .core_requirements
                .min_policy_scoped_accelerators
                .is_some()
            {
                matched_requirements
                    .push("core_requirements.min_policy_scoped_accelerators".to_string());
            }
            return ValidationReportPayloadV1 {
                verdict: ValidationVerdictV1::FitWithDegradation,
                primary_reason_code: ValidationReasonCodeV1::DegradationPathRequired,
                matched_requirements,
                failed_requirements: vec!["core_requirements.primary_capability_class".to_string()],
                evidence_refs: fallback_match.claim.evidence_refs.clone(),
                policy_refs: fallback_match.claim.rule_ids.clone(),
                assurance_mismatches: vec![],
                selected_degradation_tier: Some(tier_id.to_string()),
                warnings: vec![
                    "primary capability was unavailable or non-admissible and a degraded fallback was selected".to_string(),
                ],
                summary: format!("service profile fits with degradation via {}", tier_id),
                ..ValidationReportPayloadV1::default()
            };
        }

        if profile.degradation_ladder.is_empty() {
            return ValidationReportPayloadV1 {
                verdict: ValidationVerdictV1::Unfit,
                primary_reason_code: ValidationReasonCodeV1::PolicyNotAdmissible,
                matched_requirements,
                failed_requirements: vec!["core_requirements.primary_capability_class".to_string()],
                evidence_refs: primary_match.claim.evidence_refs.clone(),
                policy_refs: primary_match.claim.rule_ids.clone(),
                assurance_mismatches: vec![],
                selected_degradation_tier: None,
                warnings: vec![],
                summary: format_primary_capability_failure(primary_capability, Some(primary_match)),
                ..ValidationReportPayloadV1::default()
            };
        }

        return degradation_path_unavailable_report(
            contract,
            service_profile,
            matched_requirements,
            Some(primary_match),
        );
    }

    if let Some((tier_id, fallback_match)) = select_degradation_tier(contract, service_profile) {
        let mut matched_requirements = vec![
            "core_requirements.allowed_visibility_scopes".to_string(),
            format!("degradation_ladder.{tier_id}"),
        ];
        if profile
            .core_requirements
            .min_policy_scoped_accelerators
            .is_some()
        {
            matched_requirements
                .push("core_requirements.min_policy_scoped_accelerators".to_string());
        }
        return ValidationReportPayloadV1 {
            verdict: ValidationVerdictV1::FitWithDegradation,
            primary_reason_code: ValidationReasonCodeV1::DegradationPathRequired,
            matched_requirements,
            failed_requirements: vec!["core_requirements.primary_capability_class".to_string()],
            evidence_refs: fallback_match.claim.evidence_refs.clone(),
            policy_refs: fallback_match.claim.rule_ids.clone(),
            assurance_mismatches: vec![],
            selected_degradation_tier: Some(tier_id.to_string()),
            warnings: vec![
                "primary capability was not present and a degraded fallback was selected"
                    .to_string(),
            ],
            summary: format!("service profile fits with degradation via {}", tier_id),
            ..ValidationReportPayloadV1::default()
        };
    }

    if profile.degradation_ladder.is_empty() {
        return ValidationReportPayloadV1 {
            verdict: ValidationVerdictV1::Unfit,
            primary_reason_code: ValidationReasonCodeV1::CapabilityUnknown,
            matched_requirements,
            failed_requirements: vec!["core_requirements.primary_capability_class".to_string()],
            evidence_refs: vec![],
            policy_refs: vec![],
            assurance_mismatches: vec![],
            selected_degradation_tier: None,
            warnings: vec![],
            summary: "required capability is not present in the host contract".to_string(),
            ..ValidationReportPayloadV1::default()
        };
    }

    degradation_path_unavailable_report(contract, service_profile, matched_requirements, None)
}

fn runtime_thresholds_declared(service_profile: &ServiceProfileV1) -> bool {
    let requirements = &service_profile.profile.core_requirements;
    requirements.min_allocatable_cpu_logical_cores.is_some()
        || requirements.min_allocatable_memory_bytes.is_some()
}

fn runtime_requirement_keys(service_profile: &ServiceProfileV1) -> Vec<String> {
    let mut keys = Vec::new();
    if service_profile
        .profile
        .core_requirements
        .min_allocatable_cpu_logical_cores
        .is_some()
    {
        keys.push("core_requirements.min_allocatable_cpu_logical_cores".to_string());
    }
    if service_profile
        .profile
        .core_requirements
        .min_allocatable_memory_bytes
        .is_some()
    {
        keys.push("core_requirements.min_allocatable_memory_bytes".to_string());
    }
    keys
}

fn runtime_evidence_refs() -> Vec<String> {
    vec![
        "$.state.core_state.resources.allocatable_cpu_logical_cores".to_string(),
        "$.state.core_state.resources.allocatable_memory_bytes".to_string(),
    ]
}

fn format_bytes(bytes: u64) -> String {
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;

    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GiB", bytes as f64 / GIB)
    } else {
        format!("{:.2} MiB", bytes as f64 / MIB)
    }
}

fn cuda_runtime_allocatable_requirement_key() -> String {
    format!("extension_requirements.{CUDA_RUNTIME_NAMESPACE}.minimum_allocatable_memory_bytes")
}

fn cuda_runtime_device_allocatable_requirement_key() -> String {
    format!(
        "extension_requirements.{CUDA_RUNTIME_NAMESPACE}.minimum_device_allocatable_memory_bytes"
    )
}

fn cuda_runtime_qualifying_device_aggregate_allocatable_requirement_key() -> String {
    format!(
        "extension_requirements.{CUDA_RUNTIME_NAMESPACE}.minimum_qualifying_device_aggregate_allocatable_memory_bytes"
    )
}

fn cuda_runtime_namespace_requirement_key() -> String {
    format!("extension_requirements.{CUDA_RUNTIME_NAMESPACE}")
}

fn cuda_runtime_contract_evidence_ref() -> String {
    format!("$.contract.extension_contract.{CUDA_RUNTIME_NAMESPACE}")
}

fn cuda_runtime_threshold_evidence_refs() -> Vec<String> {
    vec![format!(
        "$.state.extension_state.{CUDA_RUNTIME_NAMESPACE}.allocatable_memory_bytes"
    )]
}

fn cuda_runtime_device_count_evidence_refs() -> Vec<String> {
    vec![format!(
        "$.state.extension_state.{CUDA_RUNTIME_NAMESPACE}.devices"
    )]
}

fn cuda_runtime_device_threshold_evidence_refs() -> Vec<String> {
    vec![format!(
        "$.state.extension_state.{CUDA_RUNTIME_NAMESPACE}.devices[].allocatable_memory_bytes"
    )]
}

fn cuda_runtime_evidence_refs_with_freshness(mut refs: Vec<String>) -> Vec<String> {
    refs.push("$.state.core_state.freshness.observed_at".to_string());
    refs.push("$.state.core_state.freshness.freshness_state".to_string());
    refs.sort();
    refs.dedup();
    refs
}

fn cuda_runtime_total_memory_bytes(host_state: &HostStateV1) -> Option<u64> {
    let value = host_state
        .state
        .extension_state
        .get(CUDA_RUNTIME_NAMESPACE)?;
    let state = decode_cuda_runtime_state_from_value(value).ok()?;
    match (
        &state.total_memory_bytes.state,
        &state.total_memory_bytes.value,
    ) {
        (ObservationStateV1::Observed, Some(value))
        | (ObservationStateV1::PartiallyObserved, Some(value)) => Some(*value),
        _ => None,
    }
}

fn cuda_runtime_requirement_keys(
    required_qualifying_device_count: Option<u32>,
    required_allocatable_memory_bytes: Option<u64>,
    required_device_allocatable_memory_bytes: Option<u64>,
    required_qualifying_device_aggregate_allocatable_memory_bytes: Option<u64>,
) -> Vec<String> {
    let mut keys = Vec::new();
    if required_qualifying_device_count.is_some() {
        keys.push("core_requirements.min_policy_scoped_accelerators".to_string());
    }
    if required_allocatable_memory_bytes.is_some() {
        keys.push(cuda_runtime_allocatable_requirement_key());
    }
    if required_device_allocatable_memory_bytes.is_some() {
        keys.push(cuda_runtime_device_allocatable_requirement_key());
    }
    if required_qualifying_device_aggregate_allocatable_memory_bytes.is_some() {
        keys.push(cuda_runtime_qualifying_device_aggregate_allocatable_requirement_key());
    }
    keys.sort();
    keys.dedup();
    keys
}

fn cuda_runtime_gate_evidence_refs(
    required_qualifying_device_count: Option<u32>,
    required_allocatable_memory_bytes: Option<u64>,
    required_device_allocatable_memory_bytes: Option<u64>,
    required_qualifying_device_aggregate_allocatable_memory_bytes: Option<u64>,
) -> Vec<String> {
    let mut refs = Vec::new();
    if required_qualifying_device_count.is_some() {
        refs.extend(cuda_runtime_device_count_evidence_refs());
    }
    if required_allocatable_memory_bytes.is_some() {
        refs.extend(cuda_runtime_threshold_evidence_refs());
    }
    if required_device_allocatable_memory_bytes.is_some() {
        refs.extend(cuda_runtime_device_threshold_evidence_refs());
    }
    if required_qualifying_device_aggregate_allocatable_memory_bytes.is_some() {
        refs.extend(cuda_runtime_device_count_evidence_refs());
        refs.extend(cuda_runtime_device_threshold_evidence_refs());
    }
    refs.sort();
    refs.dedup();
    refs
}

fn cuda_runtime_threshold_label(
    required_qualifying_device_count: Option<u32>,
    required_allocatable_memory_bytes: Option<u64>,
    required_device_allocatable_memory_bytes: Option<u64>,
    required_qualifying_device_aggregate_allocatable_memory_bytes: Option<u64>,
) -> &'static str {
    if required_qualifying_device_count.is_some()
        && required_qualifying_device_aggregate_allocatable_memory_bytes.is_some()
    {
        "CUDA runtime qualifying-device aggregate-memory thresholds"
    } else if required_qualifying_device_count.is_some()
        && required_allocatable_memory_bytes.is_some()
        && required_device_allocatable_memory_bytes.is_some()
    {
        "CUDA runtime qualifying-device and allocatable-memory thresholds"
    } else if required_qualifying_device_count.is_some()
        && required_device_allocatable_memory_bytes.is_some()
    {
        "CUDA runtime qualifying-device thresholds"
    } else if required_qualifying_device_count.is_some()
        && required_allocatable_memory_bytes.is_some()
    {
        "CUDA runtime device-count and allocatable-memory thresholds"
    } else if required_qualifying_device_count.is_some() {
        "CUDA runtime device-count thresholds"
    } else {
        "CUDA allocatable memory thresholds"
    }
}

fn cuda_runtime_device_allocatable_bytes(state: &CudaRuntimeDeviceStateV1) -> Option<u64> {
    match (
        &state.allocatable_memory_bytes.state,
        &state.allocatable_memory_bytes.value,
    ) {
        (ObservationStateV1::Observed, Some(value))
        | (ObservationStateV1::PartiallyObserved, Some(value)) => Some(*value),
        _ => None,
    }
}

fn cuda_runtime_qualifying_device_count(
    state: &CudaRuntimeStateV1,
    required_device_allocatable_memory_bytes: Option<u64>,
) -> u32 {
    let count = state
        .devices
        .iter()
        .filter(|device| match required_device_allocatable_memory_bytes {
            Some(minimum) => {
                cuda_runtime_device_allocatable_bytes(device).is_some_and(|value| value >= minimum)
            }
            None => true,
        })
        .count();
    u32::try_from(count).expect("CUDA device count should fit into u32")
}

fn cuda_runtime_qualifying_device_aggregate_allocatable_memory(
    state: &CudaRuntimeStateV1,
    required_device_allocatable_memory_bytes: Option<u64>,
) -> u64 {
    state
        .devices
        .iter()
        .filter_map(|device| {
            let allocatable_bytes = cuda_runtime_device_allocatable_bytes(device)?;
            match required_device_allocatable_memory_bytes {
                Some(minimum) if allocatable_bytes < minimum => None,
                _ => Some(allocatable_bytes),
            }
        })
        .sum()
}

#[derive(Debug, Clone, Copy)]
struct CudaRuntimeValidationDiagnosticSelector {
    detail_code: CudaRuntimeValidationDetailCodeV1,
    checkpoint: CudaRuntimeValidationCheckpointV1,
}

#[derive(Debug, Clone, Copy)]
struct CudaRuntimeValidationDiagnosticPayload {
    required_allocatable_memory_bytes: Option<u64>,
    observed_allocatable_memory_bytes: Option<u64>,
    observed_total_memory_bytes: Option<u64>,
    required_qualifying_device_count: Option<u32>,
    observed_qualifying_device_count: Option<u32>,
    required_device_allocatable_memory_bytes: Option<u64>,
    required_qualifying_device_aggregate_allocatable_memory_bytes: Option<u64>,
    observed_qualifying_device_aggregate_allocatable_memory_bytes: Option<u64>,
}

fn attach_cuda_runtime_validation_diagnostic(
    report: &mut ValidationReportPayloadV1,
    selector: CudaRuntimeValidationDiagnosticSelector,
    related_requirements: Vec<String>,
    evidence_refs: Vec<String>,
    payload: CudaRuntimeValidationDiagnosticPayload,
) {
    let diagnostic = CudaRuntimeValidationDiagnosticV1 {
        diagnostic_model_id: CUDA_RUNTIME_VALIDATION_DIAGNOSTIC_MODEL_ID.to_string(),
        diagnostic_model_version: 1,
        detail_code: selector.detail_code,
        checkpoint: selector.checkpoint,
        related_requirements,
        evidence_refs,
        required_allocatable_memory_bytes: payload.required_allocatable_memory_bytes,
        observed_allocatable_memory_bytes: payload.observed_allocatable_memory_bytes,
        observed_total_memory_bytes: payload.observed_total_memory_bytes,
        required_qualifying_device_count: payload.required_qualifying_device_count,
        observed_qualifying_device_count: payload.observed_qualifying_device_count,
        required_device_allocatable_memory_bytes: payload.required_device_allocatable_memory_bytes,
        required_qualifying_device_aggregate_allocatable_memory_bytes: payload
            .required_qualifying_device_aggregate_allocatable_memory_bytes,
        observed_qualifying_device_aggregate_allocatable_memory_bytes: payload
            .observed_qualifying_device_aggregate_allocatable_memory_bytes,
    };

    let value = serde_json::to_value(&diagnostic)
        .expect("CUDA runtime validation diagnostic should encode");
    report
        .extension_diagnostics
        .insert(CUDA_RUNTIME_NAMESPACE.to_string(), value);
}

fn decode_cuda_runtime_validation_diagnostic_from_report(
    report: &ValidationReportPayloadV1,
) -> Option<CudaRuntimeValidationDiagnosticV1> {
    let value = report.extension_diagnostics.get(CUDA_RUNTIME_NAMESPACE)?;
    decode_cuda_runtime_validation_diagnostic_from_value(value).ok()
}

fn cuda_runtime_required_threshold_summary(
    diagnostic: &CudaRuntimeValidationDiagnosticV1,
) -> String {
    let mut parts = Vec::new();
    if let Some(required_allocatable_memory_bytes) = diagnostic.required_allocatable_memory_bytes {
        parts.push(format!(
            "required allocatable-memory threshold {}",
            format_bytes(required_allocatable_memory_bytes)
        ));
    }
    if let Some(required_qualifying_device_count) = diagnostic.required_qualifying_device_count {
        parts.push(format!(
            "required qualifying-device count {}{}",
            required_qualifying_device_count,
            cuda_runtime_per_device_floor_suffix(diagnostic)
        ));
    }
    if let Some(required_qualifying_device_aggregate_allocatable_memory_bytes) =
        diagnostic.required_qualifying_device_aggregate_allocatable_memory_bytes
    {
        parts.push(format!(
            "required qualifying-device aggregate allocatable-memory threshold {}",
            format_bytes(required_qualifying_device_aggregate_allocatable_memory_bytes)
        ));
    }
    if parts.is_empty() {
        "unknown CUDA runtime threshold".to_string()
    } else {
        parts.join(" and ")
    }
}

fn cuda_runtime_per_device_floor_suffix(diagnostic: &CudaRuntimeValidationDiagnosticV1) -> String {
    diagnostic
        .required_device_allocatable_memory_bytes
        .map(|value| format!(" at per-device floor {}", format_bytes(value)))
        .unwrap_or_default()
}

fn build_cuda_runtime_validation_explanation(
    diagnostic: &CudaRuntimeValidationDiagnosticV1,
    reason_code: ValidationReasonCodeV1,
) -> ValidationExplanationV1 {
    let summary = match diagnostic.detail_code {
        CudaRuntimeValidationDetailCodeV1::StaticRequirementUnsatisfied => format!(
            "CUDA runtime static requirement failed before runtime headroom was evaluated; {}.",
            cuda_runtime_required_threshold_summary(diagnostic)
        ),
        CudaRuntimeValidationDetailCodeV1::RuntimeStateMissing => format!(
            "CUDA runtime state is missing for {}.",
            cuda_runtime_required_threshold_summary(diagnostic)
        ),
        CudaRuntimeValidationDetailCodeV1::RuntimeStateStale => format!(
            "CUDA runtime state is stale for {}.",
            cuda_runtime_required_threshold_summary(diagnostic)
        ),
        CudaRuntimeValidationDetailCodeV1::AllocatableMemoryInsufficient => format!(
            "CUDA allocatable memory {} is below the required threshold {}.",
            format_bytes(
                diagnostic
                    .observed_allocatable_memory_bytes
                    .expect("validated diagnostic should carry observed allocatable memory"),
            ),
            format_bytes(
                diagnostic
                    .required_allocatable_memory_bytes
                    .expect("validated diagnostic should carry required bytes"),
            )
        ),
        CudaRuntimeValidationDetailCodeV1::QualifyingDeviceCountInsufficient => format!(
            "CUDA qualifying device count {} is below the required threshold {}{}.",
            diagnostic
                .observed_qualifying_device_count
                .expect("validated diagnostic should carry observed qualifying-device count"),
            diagnostic
                .required_qualifying_device_count
                .expect("validated diagnostic should carry required qualifying-device count"),
            cuda_runtime_per_device_floor_suffix(diagnostic)
        ),
        CudaRuntimeValidationDetailCodeV1::QualifyingDeviceAggregateAllocatableMemoryInsufficient => format!(
            "CUDA qualifying-device aggregate allocatable memory {} is below the required threshold {}{}.",
            format_bytes(
                diagnostic
                    .observed_qualifying_device_aggregate_allocatable_memory_bytes
                    .expect("validated diagnostic should carry observed qualifying-device aggregate allocatable memory"),
            ),
            format_bytes(
                diagnostic
                    .required_qualifying_device_aggregate_allocatable_memory_bytes
                    .expect("validated diagnostic should carry required qualifying-device aggregate allocatable memory"),
            ),
            cuda_runtime_per_device_floor_suffix(diagnostic)
        ),
        CudaRuntimeValidationDetailCodeV1::RuntimeThresholdSatisfied => format!(
            "CUDA allocatable memory {} satisfies the required threshold {}.",
            format_bytes(
                diagnostic
                    .observed_allocatable_memory_bytes
                    .expect("validated diagnostic should carry observed allocatable memory"),
            ),
            format_bytes(
                diagnostic
                    .required_allocatable_memory_bytes
                    .expect("validated diagnostic should carry required bytes"),
            )
        ),
        CudaRuntimeValidationDetailCodeV1::QualifyingDeviceThresholdSatisfied => format!(
            "CUDA qualifying device count {} satisfies the required threshold {}{}.",
            diagnostic
                .observed_qualifying_device_count
                .expect("validated diagnostic should carry observed qualifying-device count"),
            diagnostic
                .required_qualifying_device_count
                .expect("validated diagnostic should carry required qualifying-device count"),
            cuda_runtime_per_device_floor_suffix(diagnostic)
        ),
        CudaRuntimeValidationDetailCodeV1::QualifyingDeviceAggregateAllocatableMemoryThresholdSatisfied => format!(
            "CUDA qualifying-device aggregate allocatable memory {} satisfies the required threshold {}{}.",
            format_bytes(
                diagnostic
                    .observed_qualifying_device_aggregate_allocatable_memory_bytes
                    .expect("validated diagnostic should carry observed qualifying-device aggregate allocatable memory"),
            ),
            format_bytes(
                diagnostic
                    .required_qualifying_device_aggregate_allocatable_memory_bytes
                    .expect("validated diagnostic should carry required qualifying-device aggregate allocatable memory"),
            ),
            cuda_runtime_per_device_floor_suffix(diagnostic)
        ),
    };

    ValidationExplanationV1 {
        explanation_id: format!("explain-cuda-runtime-{}", diagnostic.detail_code.as_str()),
        reason_code,
        summary,
        related_requirements: diagnostic.related_requirements.clone(),
        evidence_refs: diagnostic.evidence_refs.clone(),
        policy_refs: vec![],
    }
}

fn build_cuda_runtime_validation_remediation_hint(
    diagnostic: &CudaRuntimeValidationDiagnosticV1,
    reason_code: ValidationReasonCodeV1,
) -> Option<ValidationRemediationHintV1> {
    let hint = match diagnostic.detail_code {
        CudaRuntimeValidationDetailCodeV1::StaticRequirementUnsatisfied => {
            ValidationRemediationHintV1 {
                hint_id: "review-cuda-runtime-contract-promise".to_string(),
                reason_code,
                summary: "Review the CUDA runtime contract promise before relying on runtime memory thresholds.".to_string(),
                actions: vec![
                    ValidationRemediationActionV1 {
                        action_id: "inspect-cuda-extension-contract".to_string(),
                        summary: "Inspect the CUDA extension contract section before treating runtime headroom as relevant.".to_string(),
                    },
                    ValidationRemediationActionV1 {
                        action_id: "select-host-with-cuda-runtime".to_string(),
                        summary: "Choose a host and policy combination that derives a usable CUDA runtime promise.".to_string(),
                    },
                ],
            }
        }
        CudaRuntimeValidationDetailCodeV1::RuntimeStateMissing => ValidationRemediationHintV1 {
            hint_id: "collect-cuda-runtime-state".to_string(),
            reason_code,
            summary: "Collect host-state with the CUDA runtime namespace before rerunning validation.".to_string(),
            actions: vec![
                ValidationRemediationActionV1 {
                    action_id: "collect-fresh-host-state".to_string(),
                    summary: "Emit a fresh host-state.v2 artifact that includes CUDA runtime extension state.".to_string(),
                },
                ValidationRemediationActionV1 {
                    action_id: "inspect-cuda-runtime-state".to_string(),
                    summary: "Inspect the CUDA runtime extension state rather than relying on the top-level reason code alone.".to_string(),
                },
            ],
        },
        CudaRuntimeValidationDetailCodeV1::RuntimeStateStale => ValidationRemediationHintV1 {
            hint_id: "refresh-cuda-runtime-state".to_string(),
            reason_code,
            summary: "Refresh host-state so the CUDA runtime threshold uses current runtime evidence.".to_string(),
            actions: vec![
                ValidationRemediationActionV1 {
                    action_id: "collect-fresh-host-state".to_string(),
                    summary: "Collect a fresh host-state.v2 artifact with CUDA runtime extension state.".to_string(),
                },
                ValidationRemediationActionV1 {
                    action_id: "review-state-age-window".to_string(),
                    summary: "Review the configured max-state-age if CUDA runtime state is expiring sooner than intended.".to_string(),
                },
            ],
        },
        CudaRuntimeValidationDetailCodeV1::AllocatableMemoryInsufficient => {
            ValidationRemediationHintV1 {
                hint_id: "review-cuda-runtime-headroom".to_string(),
                reason_code,
                summary: "Choose a host with more free CUDA memory or lower the runtime threshold if the profile allows it.".to_string(),
                actions: vec![
                    ValidationRemediationActionV1 {
                        action_id: "inspect-cuda-runtime-headroom".to_string(),
                        summary: "Inspect the CUDA allocatable and total memory values recorded in the validation diagnostic.".to_string(),
                    },
                    ValidationRemediationActionV1 {
                        action_id: "select-less-loaded-gpu-host-or-lower-threshold".to_string(),
                        summary: "Choose a less loaded GPU host or lower the CUDA memory requirement only if the workload policy allows it.".to_string(),
                    },
                ],
            }
        }
        CudaRuntimeValidationDetailCodeV1::QualifyingDeviceCountInsufficient => {
            ValidationRemediationHintV1 {
                hint_id: "review-cuda-qualifying-device-count".to_string(),
                reason_code,
                summary: "Choose a host with more qualifying CUDA devices or lower the scoped GPU count only if the profile allows it.".to_string(),
                actions: vec![
                    ValidationRemediationActionV1 {
                        action_id: "inspect-cuda-qualifying-device-count".to_string(),
                        summary: "Inspect the CUDA runtime device list and qualifying-device count recorded in the validation diagnostic.".to_string(),
                    },
                    ValidationRemediationActionV1 {
                        action_id: "select-host-with-more-qualifying-gpus-or-lower-threshold".to_string(),
                        summary: "Choose a host with enough qualifying CUDA devices or lower the count only if the workload policy allows it.".to_string(),
                    },
                ],
            }
        }
        CudaRuntimeValidationDetailCodeV1::QualifyingDeviceAggregateAllocatableMemoryInsufficient => {
            ValidationRemediationHintV1 {
                hint_id: "review-cuda-qualifying-device-aggregate-memory".to_string(),
                reason_code,
                summary: "Choose a host with more allocatable memory across the qualifying CUDA devices or lower the aggregate threshold only if the profile allows it.".to_string(),
                actions: vec![
                    ValidationRemediationActionV1 {
                        action_id: "inspect-cuda-qualifying-device-aggregate-memory".to_string(),
                        summary: "Inspect the qualifying-device aggregate allocatable-memory value and per-device floor recorded in the CUDA runtime diagnostic.".to_string(),
                    },
                    ValidationRemediationActionV1 {
                        action_id: "select-host-with-more-qualifying-cuda-memory-or-lower-threshold".to_string(),
                        summary: "Choose a host with more allocatable memory across the qualifying CUDA devices or lower the aggregate threshold only if the workload policy allows it.".to_string(),
                    },
                ],
            }
        }
        CudaRuntimeValidationDetailCodeV1::RuntimeThresholdSatisfied => return None,
        CudaRuntimeValidationDetailCodeV1::QualifyingDeviceThresholdSatisfied => return None,
        CudaRuntimeValidationDetailCodeV1::QualifyingDeviceAggregateAllocatableMemoryThresholdSatisfied => return None,
    };

    Some(hint)
}

fn scalar_state_value<T: Copy>(
    field: &StateFieldV1<T>,
    requirement_key: &str,
) -> Result<T, Box<ValidationReportPayloadV1>> {
    match (&field.state, &field.value) {
        (ObservationStateV1::Observed, Some(value))
        | (ObservationStateV1::PartiallyObserved, Some(value)) => Ok(*value),
        _ => Err(Box::new(ValidationReportPayloadV1 {
            verdict: ValidationVerdictV1::Indeterminate,
            primary_reason_code: ValidationReasonCodeV1::StateMissing,
            matched_requirements: vec![],
            failed_requirements: vec![requirement_key.to_string()],
            evidence_refs: runtime_evidence_refs(),
            policy_refs: vec![],
            assurance_mismatches: vec![],
            selected_degradation_tier: None,
            warnings: vec![
                "state-aware validation requires concrete host-state values for runtime thresholds"
                    .to_string(),
            ],
            summary: "required runtime state is missing or unknown".to_string(),
            ..ValidationReportPayloadV1::default()
        })),
    }
}

fn runtime_missing_report(
    base: ValidationReportPayloadV1,
    mut missing: ValidationReportPayloadV1,
) -> ValidationReportPayloadV1 {
    missing.matched_requirements = base.matched_requirements;
    missing.policy_refs = base.policy_refs;
    missing.assurance_mismatches = base.assurance_mismatches;
    missing
}

fn runtime_extension_state_missing_or_stale_report(
    base: ValidationReportPayloadV1,
    failed_requirements: Vec<String>,
    evidence_refs: Vec<String>,
    reason_code: ValidationReasonCodeV1,
    summary: &str,
    selector: CudaRuntimeValidationDiagnosticSelector,
    payload: CudaRuntimeValidationDiagnosticPayload,
) -> ValidationReportPayloadV1 {
    let mut warnings = base.warnings.clone();
    warnings.push(summary.to_string());
    let mut matched_requirements = base.matched_requirements;
    matched_requirements.retain(|requirement| !failed_requirements.contains(requirement));
    let mut report = ValidationReportPayloadV1 {
        verdict: ValidationVerdictV1::Indeterminate,
        primary_reason_code: reason_code,
        matched_requirements,
        failed_requirements: failed_requirements.clone(),
        evidence_refs: evidence_refs.clone(),
        policy_refs: base.policy_refs,
        assurance_mismatches: base.assurance_mismatches,
        selected_degradation_tier: None,
        warnings,
        summary: summary.to_string(),
        ..ValidationReportPayloadV1::default()
    };
    attach_cuda_runtime_validation_diagnostic(
        &mut report,
        selector,
        failed_requirements,
        evidence_refs,
        payload,
    );
    report
}

fn runtime_threshold_unsatisfied_report(
    mut base: ValidationReportPayloadV1,
    failed_requirements: Vec<String>,
    summary: String,
) -> ValidationReportPayloadV1 {
    base.verdict = ValidationVerdictV1::Unfit;
    base.primary_reason_code = ValidationReasonCodeV1::RequirementUnsatisfied;
    base.failed_requirements = failed_requirements;
    base.selected_degradation_tier = None;
    base.summary = summary;
    base.evidence_refs.extend(runtime_evidence_refs());
    base.evidence_refs.sort();
    base.evidence_refs.dedup();
    base
}

fn runtime_extension_threshold_unsatisfied_report(
    mut base: ValidationReportPayloadV1,
    failed_requirements: Vec<String>,
    evidence_refs: Vec<String>,
    summary: String,
    selector: CudaRuntimeValidationDiagnosticSelector,
    payload: CudaRuntimeValidationDiagnosticPayload,
) -> ValidationReportPayloadV1 {
    base.verdict = ValidationVerdictV1::Unfit;
    base.primary_reason_code = ValidationReasonCodeV1::RequirementUnsatisfied;
    base.failed_requirements = failed_requirements.clone();
    base.matched_requirements
        .retain(|requirement| !failed_requirements.contains(requirement));
    base.selected_degradation_tier = None;
    base.summary = summary;
    base.evidence_refs.extend(evidence_refs.clone());
    base.evidence_refs.sort();
    base.evidence_refs.dedup();
    attach_cuda_runtime_validation_diagnostic(
        &mut base,
        selector,
        failed_requirements,
        evidence_refs,
        payload,
    );
    base
}

fn runtime_extension_validation_blocked_report(
    base: ValidationReportPayloadV1,
    failed_requirements: Vec<String>,
    evidence_refs: Vec<String>,
    summary: String,
) -> ValidationReportPayloadV1 {
    let mut warnings = base.warnings;
    warnings.push(summary.clone());
    ValidationReportPayloadV1 {
        verdict: ValidationVerdictV1::Indeterminate,
        primary_reason_code: ValidationReasonCodeV1::ValidationBlocked,
        matched_requirements: base.matched_requirements,
        failed_requirements,
        evidence_refs,
        policy_refs: base.policy_refs,
        assurance_mismatches: base.assurance_mismatches,
        selected_degradation_tier: None,
        warnings,
        summary,
        ..ValidationReportPayloadV1::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DegradationTierFailureReasonV1 {
    Forbidden,
    Absent,
    Inadmissible {
        matched_capability_class: String,
        summary: String,
    },
    StaticRequirementFailure {
        reason_code: ValidationReasonCodeV1,
        summary: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DegradationTierFailureV1 {
    tier_id: String,
    capability_class: String,
    reason: DegradationTierFailureReasonV1,
    evidence_refs: Vec<String>,
    policy_refs: Vec<String>,
}

fn degradation_path_unavailable_report(
    contract: &HostContractPayloadV1,
    service_profile: &ServiceProfileV1,
    matched_requirements: Vec<String>,
    primary_match: Option<CapabilityMatchV1<'_>>,
) -> ValidationReportPayloadV1 {
    let profile = &service_profile.profile;
    let failures = collect_degradation_tier_failures(contract, service_profile);
    let (evidence_refs, policy_refs) = collect_degradation_failure_refs(&failures);
    let primary_summary = format_primary_capability_failure(
        &profile.core_requirements.primary_capability_class,
        primary_match,
    );
    let tier_summaries = failures
        .iter()
        .map(format_degradation_tier_failure)
        .collect::<Vec<_>>();
    let summary = match tier_summaries.as_slice() {
        [] => format!("{primary_summary}; no configured degradation tier could be evaluated"),
        [single] => format!("{primary_summary}; {single}"),
        _ => format!(
            "{primary_summary}; no degradation tier is usable: {}",
            tier_summaries.join("; ")
        ),
    };

    ValidationReportPayloadV1 {
        verdict: ValidationVerdictV1::Unfit,
        primary_reason_code: ValidationReasonCodeV1::DegradationPathUnavailable,
        matched_requirements,
        failed_requirements: vec!["core_requirements.primary_capability_class".to_string()],
        evidence_refs,
        policy_refs,
        assurance_mismatches: vec![],
        selected_degradation_tier: None,
        warnings: vec![],
        summary,
        ..ValidationReportPayloadV1::default()
    }
}

fn collect_degradation_tier_failures(
    contract: &HostContractPayloadV1,
    service_profile: &ServiceProfileV1,
) -> Vec<DegradationTierFailureV1> {
    let mut failures = Vec::new();
    let profile = &service_profile.profile;

    for tier in &profile.degradation_ladder {
        if is_forbidden(profile, &tier.acceptable_capability_class) {
            failures.push(DegradationTierFailureV1 {
                tier_id: tier.tier_id.clone(),
                capability_class: tier.acceptable_capability_class.clone(),
                reason: DegradationTierFailureReasonV1::Forbidden,
                evidence_refs: vec![],
                policy_refs: vec![],
            });
            continue;
        }

        let Some(capability_match) =
            resolve_capability_match(contract, &tier.acceptable_capability_class)
        else {
            failures.push(DegradationTierFailureV1 {
                tier_id: tier.tier_id.clone(),
                capability_class: tier.acceptable_capability_class.clone(),
                reason: DegradationTierFailureReasonV1::Absent,
                evidence_refs: vec![],
                policy_refs: vec![],
            });
            continue;
        };

        if !capability_match.claim.admissible {
            failures.push(DegradationTierFailureV1 {
                tier_id: tier.tier_id.clone(),
                capability_class: tier.acceptable_capability_class.clone(),
                reason: DegradationTierFailureReasonV1::Inadmissible {
                    matched_capability_class: capability_match.matched_capability_class.to_string(),
                    summary: capability_match.claim.summary.clone(),
                },
                evidence_refs: capability_match.claim.evidence_refs.clone(),
                policy_refs: capability_match.claim.rule_ids.clone(),
            });
            continue;
        }

        let matched_requirements = vec![
            "core_requirements.allowed_visibility_scopes".to_string(),
            format!("degradation_ladder.{}", tier.tier_id),
        ];
        if let Some(report) = evaluate_contract_shared_static_requirements(
            contract,
            service_profile,
            matched_requirements,
        ) {
            failures.push(DegradationTierFailureV1 {
                tier_id: tier.tier_id.clone(),
                capability_class: tier.acceptable_capability_class.clone(),
                reason: DegradationTierFailureReasonV1::StaticRequirementFailure {
                    reason_code: report.primary_reason_code,
                    summary: report.summary,
                },
                evidence_refs: report.evidence_refs,
                policy_refs: report.policy_refs,
            });
        }
    }

    failures
}

fn collect_degradation_failure_refs(
    failures: &[DegradationTierFailureV1],
) -> (Vec<String>, Vec<String>) {
    let mut evidence_refs = failures
        .iter()
        .flat_map(|failure| failure.evidence_refs.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut policy_refs = failures
        .iter()
        .flat_map(|failure| failure.policy_refs.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    evidence_refs.sort();
    policy_refs.sort();
    (evidence_refs, policy_refs)
}

fn format_primary_capability_failure(
    primary_capability: &str,
    primary_match: Option<CapabilityMatchV1<'_>>,
) -> String {
    match primary_match {
        Some(capability_match) if !capability_match.claim.admissible => {
            if capability_match.matched_capability_class == primary_capability {
                format!(
                    "primary capability {primary_capability} is not admissible under the derived contract: {}",
                    capability_match.claim.summary
                )
            } else {
                format!(
                    "primary capability {primary_capability} is only available via {}, but that capability is not admissible under the derived contract: {}",
                    capability_match.matched_capability_class,
                    capability_match.claim.summary
                )
            }
        }
        Some(_) => format!(
            "primary capability {primary_capability} remained unresolved for degradation reporting"
        ),
        None => format!("primary capability {primary_capability} is absent from the host contract"),
    }
}

fn format_degradation_tier_failure(failure: &DegradationTierFailureV1) -> String {
    match &failure.reason {
        DegradationTierFailureReasonV1::Forbidden => format!(
            "{} requires {}, but that capability is forbidden by the service profile",
            failure.tier_id, failure.capability_class
        ),
        DegradationTierFailureReasonV1::Absent => format!(
            "{} requires {}, but that capability is absent from the host contract",
            failure.tier_id, failure.capability_class
        ),
        DegradationTierFailureReasonV1::Inadmissible {
            matched_capability_class,
            summary,
        } => {
            if matched_capability_class == &failure.capability_class {
                format!(
                    "{} requires {}, but that capability is not admissible under the derived contract: {}",
                    failure.tier_id, failure.capability_class, summary
                )
            } else {
                format!(
                    "{} requires {}, but only {} is available via subsumption and that capability is not admissible under the derived contract: {}",
                    failure.tier_id,
                    failure.capability_class,
                    matched_capability_class,
                    summary
                )
            }
        }
        DegradationTierFailureReasonV1::StaticRequirementFailure {
            reason_code,
            summary,
        } => {
            let descriptor = if matches!(reason_code, ValidationReasonCodeV1::EvidenceIncomplete) {
                "static requirement evidence remains incomplete"
            } else {
                "static requirement check failed"
            };
            format!(
                "{} requires {}, but {}: {}",
                failure.tier_id, failure.capability_class, descriptor, summary
            )
        }
    }
}

fn select_degradation_tier<'a>(
    contract: &'a HostContractPayloadV1,
    service_profile: &'a ServiceProfileV1,
) -> Option<(&'a str, CapabilityMatchV1<'a>)> {
    // Degradation ladder order is semantic. The first admissible fallback tier wins.
    let profile = &service_profile.profile;
    for tier in &profile.degradation_ladder {
        if is_forbidden(profile, &tier.acceptable_capability_class) {
            continue;
        }
        if let Some(capability_match) =
            resolve_capability_match(contract, &tier.acceptable_capability_class)
        {
            if capability_match.claim.admissible {
                let matched_requirements = vec![
                    "core_requirements.allowed_visibility_scopes".to_string(),
                    format!("degradation_ladder.{}", tier.tier_id),
                ];
                if evaluate_contract_shared_static_requirements(
                    contract,
                    service_profile,
                    matched_requirements,
                )
                .is_none()
                {
                    return Some((&tier.tier_id, capability_match));
                }
            }
        }
    }

    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CapabilityMatchV1<'a> {
    matched_capability_class: &'a str,
    claim: &'a DerivedCapabilityClaimV1,
}

fn resolve_capability_match<'a>(
    contract: &'a HostContractPayloadV1,
    required_capability_class: &str,
) -> Option<CapabilityMatchV1<'a>> {
    let exact_match = contract
        .core_contract
        .capability_classes
        .get_key_value(required_capability_class)
        .map(|(capability_class, claim)| CapabilityMatchV1 {
            matched_capability_class: capability_class.as_str(),
            claim,
        });
    if exact_match.is_some_and(|capability_match| capability_match.claim.admissible) {
        return exact_match;
    }

    for subsuming_capability_class in subsuming_capability_classes(required_capability_class) {
        if let Some((capability_class, claim)) = contract
            .core_contract
            .capability_classes
            .get_key_value(*subsuming_capability_class)
        {
            if claim.admissible {
                return Some(CapabilityMatchV1 {
                    matched_capability_class: capability_class.as_str(),
                    claim,
                });
            }
        }
    }

    if exact_match.is_some() {
        return exact_match;
    }

    for subsuming_capability_class in subsuming_capability_classes(required_capability_class) {
        if let Some((capability_class, claim)) = contract
            .core_contract
            .capability_classes
            .get_key_value(*subsuming_capability_class)
        {
            return Some(CapabilityMatchV1 {
                matched_capability_class: capability_class.as_str(),
                claim,
            });
        }
    }

    None
}

fn subsuming_capability_classes(required_capability_class: &str) -> &'static [&'static str] {
    match required_capability_class {
        "general_compute" => &["gpu_accelerated"],
        _ => &[],
    }
}

fn collect_forbidden_contract_capabilities<'a>(
    contract: &'a HostContractPayloadV1,
    profile: &'a crate::artifacts::service_profile_v1::ServiceProfilePayloadV1,
) -> Vec<(&'a str, &'a DerivedCapabilityClaimV1)> {
    contract
        .core_contract
        .capability_classes
        .iter()
        .filter_map(|(capability_class, claim)| {
            is_forbidden(profile, capability_class).then_some((capability_class.as_str(), claim))
        })
        .collect()
}

fn requirements_satisfied_summary(
    required_capability_class: &str,
    matched_capability_class: &str,
) -> String {
    if required_capability_class == matched_capability_class {
        format!(
            "service profile fits the {} capability baseline",
            required_capability_class
        )
    } else {
        format!(
            "service profile fits the {} capability baseline via {}",
            required_capability_class, matched_capability_class
        )
    }
}

fn is_forbidden(
    profile: &crate::artifacts::service_profile_v1::ServiceProfilePayloadV1,
    capability_class: &str,
) -> bool {
    profile
        .exclusions
        .forbidden_capability_classes
        .iter()
        .any(|value| value == capability_class)
}

fn predicate_label(predicate: AssurancePredicateV1) -> &'static str {
    match predicate {
        AssurancePredicateV1::LocallyVerifiedRequired => "locally_verified_required",
        AssurancePredicateV1::HardwareAttestedRequired => "hardware_attested_required",
    }
}

fn evaluate_explicit_assurance_requirements(
    service_profile: &ServiceProfileV1,
    claim: &DerivedCapabilityClaimV1,
    matched_requirements: Vec<String>,
) -> Option<ValidationReportPayloadV1> {
    for requirement in &service_profile.profile.assurance_requirements {
        if !requirement_applies(
            requirement,
            &service_profile
                .profile
                .core_requirements
                .primary_capability_class,
        ) {
            continue;
        }

        if !requirement
            .accepted_assurance_sources
            .contains(&claim.claim_metadata.assurance_source)
        {
            return Some(ValidationReportPayloadV1 {
                verdict: ValidationVerdictV1::Unfit,
                primary_reason_code: ValidationReasonCodeV1::AssuranceSourceNotAccepted,
                matched_requirements,
                failed_requirements: vec![format!("assurance_requirements.{}", requirement.target)],
                evidence_refs: claim.evidence_refs.clone(),
                policy_refs: claim.rule_ids.clone(),
                assurance_mismatches: vec![format!(
                    "{}:source:{}",
                    requirement.target,
                    claim.claim_metadata.assurance_source.as_str()
                )],
                selected_degradation_tier: None,
                warnings: vec![],
                summary: format!(
                    "assurance source {} is outside the accepted set for {}",
                    claim.claim_metadata.assurance_source.as_str(),
                    requirement.target
                ),
                ..ValidationReportPayloadV1::default()
            });
        }

        let stage_rejected = !requirement
            .accepted_derivation_stages
            .contains(&claim.claim_metadata.derivation_stage)
            || (!requirement.allow_policy_asserted
                && claim.claim_metadata.derivation_stage == DerivationStageV1::PolicyAsserted);
        if stage_rejected {
            return Some(ValidationReportPayloadV1 {
                verdict: ValidationVerdictV1::Unfit,
                primary_reason_code: ValidationReasonCodeV1::AssuranceDerivationStageNotAccepted,
                matched_requirements,
                failed_requirements: vec![format!("assurance_requirements.{}", requirement.target)],
                evidence_refs: claim.evidence_refs.clone(),
                policy_refs: claim.rule_ids.clone(),
                assurance_mismatches: vec![format!(
                    "{}:stage:{}",
                    requirement.target,
                    claim.claim_metadata.derivation_stage.as_str()
                )],
                selected_degradation_tier: None,
                warnings: vec![],
                summary: format!(
                    "derivation stage {} is outside the accepted set for {}",
                    claim.claim_metadata.derivation_stage.as_str(),
                    requirement.target
                ),
                ..ValidationReportPayloadV1::default()
            });
        }
    }

    None
}

fn requirement_applies(
    requirement: &ExplicitAssuranceRequirementV1,
    primary_capability_class: &str,
) -> bool {
    requirement.target == "primary_capability" || requirement.target == primary_capability_class
}

fn evaluate_contract_topology_requirements(
    contract: &HostContractPayloadV1,
    service_profile: &ServiceProfileV1,
    matched_requirements: Vec<String>,
) -> Option<ValidationReportPayloadV1> {
    // Missing topology counters stay fail-closed because these requirements usually encode
    // placement constraints rather than soft preferences.
    let requirements = &service_profile.profile.core_requirements;
    let topology = &contract.core_contract.topology_summary;

    if let Some(min_numa_nodes) = requirements.min_numa_nodes {
        match topology.numa_nodes {
            Some(value) if value >= min_numa_nodes => {}
            Some(value) => {
                return Some(topology_report(
                    ValidationVerdictV1::Unfit,
                    matched_requirements,
                    "core_requirements.min_numa_nodes",
                    format!(
                        "contract NUMA node count {} is below the required minimum {}",
                        value, min_numa_nodes
                    ),
                ));
            }
            None => {
                return Some(topology_report(
                    ValidationVerdictV1::Indeterminate,
                    matched_requirements,
                    "core_requirements.min_numa_nodes",
                    "contract topology summary does not expose NUMA node count".to_string(),
                ));
            }
        }
    }

    if let Some(max_numa_nodes) = requirements.max_numa_nodes {
        match topology.numa_nodes {
            Some(value) if value <= max_numa_nodes => {}
            Some(value) => {
                return Some(topology_report(
                    ValidationVerdictV1::Unfit,
                    matched_requirements,
                    "core_requirements.max_numa_nodes",
                    format!(
                        "contract NUMA node count {} exceeds the allowed maximum {}",
                        value, max_numa_nodes
                    ),
                ));
            }
            None => {
                return Some(topology_report(
                    ValidationVerdictV1::Indeterminate,
                    matched_requirements,
                    "core_requirements.max_numa_nodes",
                    "contract topology summary does not expose NUMA node count".to_string(),
                ));
            }
        }
    }

    if let Some(min_cpu_packages) = requirements.min_cpu_packages {
        match topology.cpu_packages {
            Some(value) if value >= min_cpu_packages => {}
            Some(value) => {
                return Some(topology_report(
                    ValidationVerdictV1::Unfit,
                    matched_requirements,
                    "core_requirements.min_cpu_packages",
                    format!(
                        "contract CPU package count {} is below the required minimum {}",
                        value, min_cpu_packages
                    ),
                ));
            }
            None => {
                return Some(topology_report(
                    ValidationVerdictV1::Indeterminate,
                    matched_requirements,
                    "core_requirements.min_cpu_packages",
                    "contract topology summary does not expose CPU package count".to_string(),
                ));
            }
        }
    }

    None
}

fn evaluate_contract_accelerator_locality_requirements(
    contract: &HostContractPayloadV1,
    service_profile: &ServiceProfileV1,
    matched_requirements: Vec<String>,
) -> Option<ValidationReportPayloadV1> {
    let requirements = &service_profile.profile.core_requirements;
    if !requirements.require_accelerator_locality_known
        && requirements.max_accelerator_numa_nodes.is_none()
    {
        return None;
    }

    let summary = &contract.core_contract.accelerator_summary;
    let total_accelerators = match summary.total_accelerators {
        Some(0) => {
            return Some(accelerator_locality_report(
                ValidationVerdictV1::Unfit,
                matched_requirements,
                if requirements.require_accelerator_locality_known {
                    "core_requirements.require_accelerator_locality_known"
                } else {
                    "core_requirements.max_accelerator_numa_nodes"
                },
                "contract accelerator summary reports no accelerators for an accelerator-locality-sensitive profile".to_string(),
            ));
        }
        Some(value) => value,
        None => {
            return Some(accelerator_locality_report(
                ValidationVerdictV1::Indeterminate,
                matched_requirements,
                if requirements.require_accelerator_locality_known {
                    "core_requirements.require_accelerator_locality_known"
                } else {
                    "core_requirements.max_accelerator_numa_nodes"
                },
                "contract accelerator summary does not expose accelerator locality".to_string(),
            ));
        }
    };

    if requirements.require_accelerator_locality_known {
        match summary.accelerators_with_known_numa_node {
            Some(value) if value == total_accelerators => {}
            Some(value) => {
                return Some(accelerator_locality_report(
                    ValidationVerdictV1::Indeterminate,
                    matched_requirements,
                    "core_requirements.require_accelerator_locality_known",
                    format!(
                        "accelerator locality is known for only {} of {} accelerators",
                        value, total_accelerators
                    ),
                ));
            }
            None => {
                return Some(accelerator_locality_report(
                    ValidationVerdictV1::Indeterminate,
                    matched_requirements,
                    "core_requirements.require_accelerator_locality_known",
                    "contract accelerator summary does not expose accelerator locality".to_string(),
                ));
            }
        }
    }

    if let Some(max_accelerator_numa_nodes) = requirements.max_accelerator_numa_nodes {
        match summary.accelerators_with_known_numa_node {
            Some(value) if value == total_accelerators => {
                let distinct_numa_nodes = u32::try_from(summary.accelerator_numa_nodes.len())
                    .ok()
                    .unwrap_or(u32::MAX);
                if distinct_numa_nodes > max_accelerator_numa_nodes {
                    return Some(accelerator_locality_report(
                        ValidationVerdictV1::Unfit,
                        matched_requirements,
                        "core_requirements.max_accelerator_numa_nodes",
                        format!(
                            "contract accelerator locality spans {} NUMA nodes, exceeding the allowed maximum {}",
                            distinct_numa_nodes, max_accelerator_numa_nodes
                        ),
                    ));
                }
            }
            Some(value) => {
                return Some(accelerator_locality_report(
                    ValidationVerdictV1::Indeterminate,
                    matched_requirements,
                    "core_requirements.max_accelerator_numa_nodes",
                    format!(
                        "accelerator locality is known for only {} of {} accelerators, so NUMA spread remains unresolved",
                        value, total_accelerators
                    ),
                ));
            }
            None => {
                return Some(accelerator_locality_report(
                    ValidationVerdictV1::Indeterminate,
                    matched_requirements,
                    "core_requirements.max_accelerator_numa_nodes",
                    "contract accelerator summary does not expose accelerator locality".to_string(),
                ));
            }
        }
    }

    None
}

fn evaluate_contract_shared_static_requirements(
    contract: &HostContractPayloadV1,
    service_profile: &ServiceProfileV1,
    matched_requirements: Vec<String>,
) -> Option<ValidationReportPayloadV1> {
    if let Some(report) = evaluate_contract_topology_requirements(
        contract,
        service_profile,
        matched_requirements.clone(),
    ) {
        return Some(report);
    }
    if let Some(report) = evaluate_contract_accelerator_locality_requirements(
        contract,
        service_profile,
        matched_requirements.clone(),
    ) {
        return Some(report);
    }
    if let Some(report) = evaluate_contract_network_requirements(
        contract,
        service_profile,
        matched_requirements.clone(),
    ) {
        return Some(report);
    }
    evaluate_contract_policy_scoped_accelerator_count_requirement(
        contract,
        service_profile,
        matched_requirements,
    )
}

fn evaluate_contract_policy_scoped_accelerator_count_requirement(
    contract: &HostContractPayloadV1,
    service_profile: &ServiceProfileV1,
    matched_requirements: Vec<String>,
) -> Option<ValidationReportPayloadV1> {
    let required_minimum = service_profile
        .profile
        .core_requirements
        .min_policy_scoped_accelerators?;

    let summary = &contract.core_contract.accelerator_summary;
    let evidence_refs = vec![
        "$.contract.accelerator_summary.policy_scoped_confirmed_accelerators".to_string(),
        "$.contract.accelerator_summary.policy_scoped_unresolved_accelerators".to_string(),
        "$.contract.accelerator_summary.policy_scoped_inventory_complete".to_string(),
    ];
    let failed_requirement = "core_requirements.min_policy_scoped_accelerators";

    let Some(confirmed_count) = summary.policy_scoped_confirmed_accelerators else {
        return Some(ValidationReportPayloadV1 {
            verdict: ValidationVerdictV1::Indeterminate,
            primary_reason_code: ValidationReasonCodeV1::EvidenceIncomplete,
            matched_requirements,
            failed_requirements: vec![failed_requirement.to_string()],
            evidence_refs,
            policy_refs: vec![],
            assurance_mismatches: vec![],
            selected_degradation_tier: None,
            warnings: vec![],
            summary:
                "contract accelerator summary does not expose a policy-scoped accelerator count"
                    .to_string(),
            ..ValidationReportPayloadV1::default()
        });
    };

    if confirmed_count < required_minimum {
        return Some(ValidationReportPayloadV1 {
            verdict: ValidationVerdictV1::Unfit,
            primary_reason_code: ValidationReasonCodeV1::RequirementUnsatisfied,
            matched_requirements,
            failed_requirements: vec![failed_requirement.to_string()],
            evidence_refs,
            policy_refs: vec![],
            assurance_mismatches: vec![],
            selected_degradation_tier: None,
            warnings: vec![],
            summary: format!(
                "contract policy-scoped accelerator count {} is below the required minimum {}",
                confirmed_count, required_minimum
            ),
            ..ValidationReportPayloadV1::default()
        });
    }

    None
}

fn topology_report(
    verdict: ValidationVerdictV1,
    matched_requirements: Vec<String>,
    failed_requirement: &str,
    summary: String,
) -> ValidationReportPayloadV1 {
    ValidationReportPayloadV1 {
        verdict,
        primary_reason_code: ValidationReasonCodeV1::TopologyMismatch,
        matched_requirements,
        failed_requirements: vec![failed_requirement.to_string()],
        evidence_refs: vec!["$.contract.topology_summary".to_string()],
        policy_refs: vec![],
        assurance_mismatches: vec![],
        selected_degradation_tier: None,
        warnings: vec![],
        summary,
        ..ValidationReportPayloadV1::default()
    }
}

fn accelerator_locality_report(
    verdict: ValidationVerdictV1,
    matched_requirements: Vec<String>,
    failed_requirement: &str,
    summary: String,
) -> ValidationReportPayloadV1 {
    ValidationReportPayloadV1 {
        verdict,
        primary_reason_code: ValidationReasonCodeV1::TopologyMismatch,
        matched_requirements,
        failed_requirements: vec![failed_requirement.to_string()],
        evidence_refs: vec![
            "$.contract.accelerator_summary.total_accelerators".to_string(),
            "$.contract.accelerator_summary.accelerators_with_known_numa_node".to_string(),
            "$.contract.accelerator_summary.accelerator_numa_nodes".to_string(),
        ],
        policy_refs: vec![],
        assurance_mismatches: vec![],
        selected_degradation_tier: None,
        warnings: vec![],
        summary,
        ..ValidationReportPayloadV1::default()
    }
}

fn evaluate_contract_network_requirements(
    contract: &HostContractPayloadV1,
    service_profile: &ServiceProfileV1,
    matched_requirements: Vec<String>,
) -> Option<ValidationReportPayloadV1> {
    // Network checks use the contract summary rather than raw survey interfaces so policy-shaped
    // host promises remain the only surface validation depends on here.
    let requirements = &service_profile.profile.core_requirements;
    let network = &contract.core_contract.network_summary;

    if let Some(min_non_loopback_interfaces) = requirements.min_non_loopback_interfaces {
        match network.non_loopback_interfaces {
            Some(value) if value >= min_non_loopback_interfaces => {}
            Some(value) => {
                return Some(network_report(
                    ValidationVerdictV1::Unfit,
                    matched_requirements,
                    "core_requirements.min_non_loopback_interfaces",
                    format!(
                        "contract non-loopback interface count {} is below the required minimum {}",
                        value, min_non_loopback_interfaces
                    ),
                ));
            }
            None => {
                return Some(network_report(
                    ValidationVerdictV1::Indeterminate,
                    matched_requirements,
                    "core_requirements.min_non_loopback_interfaces",
                    "contract network summary does not expose non-loopback interface count"
                        .to_string(),
                ));
            }
        }
    }

    if let Some(min_network_link_speed_mbps) = requirements.min_network_link_speed_mbps {
        match network.max_observed_speed_mbps {
            Some(value) if value >= min_network_link_speed_mbps => {}
            Some(value) => {
                return Some(network_report(
                    ValidationVerdictV1::Unfit,
                    matched_requirements,
                    "core_requirements.min_network_link_speed_mbps",
                    format!(
                        "contract maximum observed network speed {} Mbps is below the required minimum {} Mbps",
                        value, min_network_link_speed_mbps
                    ),
                ));
            }
            None => {
                return Some(network_report(
                    ValidationVerdictV1::Indeterminate,
                    matched_requirements,
                    "core_requirements.min_network_link_speed_mbps",
                    "contract network summary does not expose a maximum observed network speed"
                        .to_string(),
                ));
            }
        }
    }

    if !requirements.required_network_interface_kinds.is_empty() {
        if network.interface_kinds.is_empty() {
            return Some(network_report(
                ValidationVerdictV1::Indeterminate,
                matched_requirements,
                "core_requirements.required_network_interface_kinds",
                "contract network summary does not expose interface kinds".to_string(),
            ));
        }
        let available_kinds = network
            .interface_kinds
            .iter()
            .map(|kind| kind.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let missing_kinds = requirements
            .required_network_interface_kinds
            .iter()
            .filter(|kind| !available_kinds.contains(kind.as_str()))
            .map(|kind| kind.as_str().to_string())
            .collect::<Vec<_>>();
        if !missing_kinds.is_empty() {
            return Some(network_report(
                ValidationVerdictV1::Unfit,
                matched_requirements,
                "core_requirements.required_network_interface_kinds",
                format!(
                    "contract network summary is missing required interface kinds: {}",
                    missing_kinds.join(", ")
                ),
            ));
        }
    }

    None
}

fn network_report(
    verdict: ValidationVerdictV1,
    matched_requirements: Vec<String>,
    failed_requirement: &str,
    summary: String,
) -> ValidationReportPayloadV1 {
    ValidationReportPayloadV1 {
        verdict,
        primary_reason_code: ValidationReasonCodeV1::NetworkMismatch,
        matched_requirements,
        failed_requirements: vec![failed_requirement.to_string()],
        evidence_refs: vec!["$.contract.network_summary".to_string()],
        policy_refs: vec![],
        assurance_mismatches: vec![],
        selected_degradation_tier: None,
        warnings: vec![],
        summary,
        ..ValidationReportPayloadV1::default()
    }
}

fn evaluate_runtime_topology_requirements(
    service_profile: &ServiceProfileV1,
    host_state: &HostStateV1,
    base: &ValidationReportPayloadV1,
) -> Option<ValidationReportPayloadV1> {
    let requirements = &service_profile.profile.core_requirements;
    let visible_numa_nodes = match (
        host_state
            .state
            .core_state
            .topology
            .visible_numa_nodes
            .state
            .clone(),
        host_state
            .state
            .core_state
            .topology
            .visible_numa_nodes
            .value,
    ) {
        (ObservationStateV1::Observed | ObservationStateV1::PartiallyObserved, Some(value)) => {
            Some(value)
        }
        _ => None,
    };

    if let Some(min_numa_nodes) = requirements.min_numa_nodes {
        match visible_numa_nodes {
            Some(value) if value >= min_numa_nodes => {}
            Some(value) => {
                return Some(ValidationReportPayloadV1 {
                    verdict: ValidationVerdictV1::Unfit,
                    primary_reason_code: ValidationReasonCodeV1::TopologyMismatch,
                    matched_requirements: base.matched_requirements.clone(),
                    failed_requirements: vec!["core_requirements.min_numa_nodes".to_string()],
                    evidence_refs: vec![
                        "$.state.core_state.topology.visible_numa_nodes".to_string()
                    ],
                    policy_refs: base.policy_refs.clone(),
                    assurance_mismatches: base.assurance_mismatches.clone(),
                    selected_degradation_tier: None,
                    warnings: vec![],
                    summary: format!(
                        "visible runtime NUMA node count {} is below the required minimum {}",
                        value, min_numa_nodes
                    ),
                    ..ValidationReportPayloadV1::default()
                });
            }
            None => {
                return Some(ValidationReportPayloadV1 {
                    verdict: ValidationVerdictV1::Indeterminate,
                    primary_reason_code: ValidationReasonCodeV1::TopologyMismatch,
                    matched_requirements: base.matched_requirements.clone(),
                    failed_requirements: vec!["core_requirements.min_numa_nodes".to_string()],
                    evidence_refs: vec![
                        "$.state.core_state.topology.visible_numa_nodes".to_string()
                    ],
                    policy_refs: base.policy_refs.clone(),
                    assurance_mismatches: base.assurance_mismatches.clone(),
                    selected_degradation_tier: None,
                    warnings: vec![],
                    summary: "runtime topology summary does not expose visible NUMA node count"
                        .to_string(),
                    ..ValidationReportPayloadV1::default()
                });
            }
        }
    }

    None
}

fn evaluate_runtime_operability(
    service_profile: &ServiceProfileV1,
    host_state: &HostStateV1,
    base: ValidationReportPayloadV1,
) -> Option<ValidationReportPayloadV1> {
    // Runtime operability can only narrow a previously acceptable static result by marking the
    // selected primary capability as degraded at the moment of validation.
    let primary_capability = &service_profile
        .profile
        .core_requirements
        .primary_capability_class;
    if host_state
        .state
        .core_state
        .operability
        .degraded_capability_classes
        .iter()
        .any(|value| value == primary_capability)
    {
        return Some(ValidationReportPayloadV1 {
            verdict: ValidationVerdictV1::Unfit,
            primary_reason_code: ValidationReasonCodeV1::CapabilityDegraded,
            matched_requirements: base.matched_requirements,
            failed_requirements: vec!["state.operability.degraded_capability_classes".to_string()],
            evidence_refs: vec![
                "$.state.core_state.operability.degraded_capability_classes".to_string()
            ],
            policy_refs: base.policy_refs,
            assurance_mismatches: base.assurance_mismatches,
            selected_degradation_tier: None,
            warnings: vec![],
            summary: format!(
                "runtime operability reports the primary capability {} as degraded",
                primary_capability
            ),
            ..ValidationReportPayloadV1::default()
        });
    }

    None
}
