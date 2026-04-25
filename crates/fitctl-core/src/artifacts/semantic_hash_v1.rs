// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Canonical semantic projections and hashing helpers for supported artifact families.

use std::cmp::Ordering;

use serde::ser::{SerializeMap, SerializeSeq};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::artifacts::batch_classification_report_v1::{
    BatchClassificationBasisV1, BatchClassificationContractRefV1,
    BatchClassificationReportPayloadV1, BatchClassificationReportV1,
    BatchClassificationServiceProfileRefV1, BatchClassificationStateRefV1,
};
use crate::artifacts::config_bundle_v1::{ConfigBundleBasisV1, ConfigBundleV1};
use crate::artifacts::contract_v1::ContractExtensionBasisV1;
use crate::artifacts::contract_v1::HostContractV1;
use crate::artifacts::decision_bundle_v1::{DecisionBundleBasisV1, DecisionBundleV1};
use crate::artifacts::recommendation_report_v1::{
    RecommendationBasisV1, RecommendationConfidenceV1, RecommendationFreshnessStateV1,
    RecommendationReportPayloadV1, RecommendationReportV1,
};
use crate::artifacts::service_profile_v1::{
    AssurancePredicateV1, DegradationTierV1, ExplicitAssuranceRequirementV1, ServiceExclusionsV1,
    ServicePreferencesV1, ServiceProfilePayloadV1, ServiceProfileV1, ServiceRequirementsV1,
};
use crate::artifacts::state_v1::{
    FreshnessStateV1, HostRuntimeResourcesV1, HostStateExecutionBoundariesV1,
    HostStateOperabilityV1, HostStatePayloadV1, HostStateTopologyV1, HostStateV1,
    StateCollectionModeV1, StateSectionMetadataV1,
};
use crate::artifacts::survey_v1::HostSurveyV1;
use crate::artifacts::validation_report_v1::{
    ValidationBasisV1, ValidationReportPayloadV1, ValidationReportV1,
};
use crate::artifacts::validation_v1::{
    validate_batch_classification_report, validate_config_bundle, validate_decision_bundle,
    validate_host_contract, validate_host_state, validate_host_survey,
    validate_recommendation_report, validate_service_profile, validate_validation_report,
    ArtifactValidationError,
};
use crate::config::ResolvedConfigV1;
use crate::policy::PolicyDocumentV1;
use crate::verify::{TrustPolicyV1, VerificationBundleV1};

/// Hash the survey's canonical semantic projection rather than its presentation envelope.
pub fn semantic_hash_hex_for_survey(
    survey: &HostSurveyV1,
) -> Result<String, ArtifactValidationError> {
    validate_host_survey(survey)?;

    let projection = SurveySemanticProjection::from(survey);
    canonical_cbor_sha256_hex(&projection)
}

pub fn core_semantic_hash_hex_for_survey(
    survey: &HostSurveyV1,
) -> Result<String, ArtifactValidationError> {
    validate_host_survey(survey)?;

    let projection = CoreSurveySemanticProjection::from(survey);
    canonical_cbor_sha256_hex(&projection)
}

pub fn semantic_cbor_bytes_for_survey(
    survey: &HostSurveyV1,
) -> Result<Vec<u8>, ArtifactValidationError> {
    semantic_bytes_for_survey(survey)
}

/// Expose the canonical semantic bytes that signatures and semantic hashes bind to.
pub fn semantic_bytes_for_survey(
    survey: &HostSurveyV1,
) -> Result<Vec<u8>, ArtifactValidationError> {
    validate_host_survey(survey)?;

    let projection = SurveySemanticProjection::from(survey);
    canonical_cbor_bytes(&projection)
}

pub fn semantic_hash_hex_for_contract(
    contract: &HostContractV1,
) -> Result<String, ArtifactValidationError> {
    validate_host_contract(contract)?;

    let projection = ContractSemanticProjection::from(contract);
    canonical_cbor_sha256_hex(&projection)
}

pub fn semantic_cbor_bytes_for_contract(
    contract: &HostContractV1,
) -> Result<Vec<u8>, ArtifactValidationError> {
    semantic_bytes_for_contract(contract)
}

pub fn semantic_bytes_for_contract(
    contract: &HostContractV1,
) -> Result<Vec<u8>, ArtifactValidationError> {
    validate_host_contract(contract)?;

    let projection = ContractSemanticProjection::from(contract);
    canonical_cbor_bytes(&projection)
}

pub fn semantic_hash_hex_for_service_profile(
    profile: &ServiceProfileV1,
) -> Result<String, ArtifactValidationError> {
    validate_service_profile(profile)?;

    let projection = ServiceProfileSemanticProjection::from(profile);
    canonical_cbor_sha256_hex(&projection)
}

pub fn semantic_cbor_bytes_for_service_profile(
    profile: &ServiceProfileV1,
) -> Result<Vec<u8>, ArtifactValidationError> {
    semantic_bytes_for_service_profile(profile)
}

pub fn semantic_bytes_for_service_profile(
    profile: &ServiceProfileV1,
) -> Result<Vec<u8>, ArtifactValidationError> {
    validate_service_profile(profile)?;

    let projection = ServiceProfileSemanticProjection::from(profile);
    canonical_cbor_bytes(&projection)
}

pub fn semantic_hash_hex_for_state(state: &HostStateV1) -> Result<String, ArtifactValidationError> {
    validate_host_state(state)?;

    let projection = StateSemanticProjection::from(state);
    canonical_cbor_sha256_hex(&projection)
}

pub fn semantic_cbor_bytes_for_state(
    state: &HostStateV1,
) -> Result<Vec<u8>, ArtifactValidationError> {
    semantic_bytes_for_state(state)
}

pub fn semantic_bytes_for_state(state: &HostStateV1) -> Result<Vec<u8>, ArtifactValidationError> {
    validate_host_state(state)?;

    let projection = StateSemanticProjection::from(state);
    canonical_cbor_bytes(&projection)
}

pub fn semantic_hash_hex_for_validation_report(
    report: &ValidationReportV1,
) -> Result<String, ArtifactValidationError> {
    validate_validation_report(report)?;

    let projection = ValidationReportSemanticProjection::from(report);
    canonical_cbor_sha256_hex(&projection)
}

pub fn semantic_cbor_bytes_for_validation_report(
    report: &ValidationReportV1,
) -> Result<Vec<u8>, ArtifactValidationError> {
    semantic_bytes_for_validation_report(report)
}

pub fn semantic_bytes_for_validation_report(
    report: &ValidationReportV1,
) -> Result<Vec<u8>, ArtifactValidationError> {
    validate_validation_report(report)?;

    let projection = ValidationReportSemanticProjection::from(report);
    canonical_cbor_bytes(&projection)
}

pub fn semantic_hash_hex_for_recommendation_report(
    report: &RecommendationReportV1,
) -> Result<String, ArtifactValidationError> {
    validate_recommendation_report(report)?;

    let projection = RecommendationReportSemanticProjection::from(report);
    canonical_cbor_sha256_hex(&projection)
}

pub fn semantic_hash_hex_for_batch_classification_report(
    report: &BatchClassificationReportV1,
) -> Result<String, ArtifactValidationError> {
    validate_batch_classification_report(report)?;

    let projection = BatchClassificationReportSemanticProjection::from(report);
    canonical_cbor_sha256_hex(&projection)
}

pub fn semantic_hash_hex_for_decision_bundle(
    bundle: &DecisionBundleV1,
) -> Result<String, ArtifactValidationError> {
    validate_decision_bundle(bundle)?;

    let projection = DecisionBundleSemanticProjection::from(bundle);
    canonical_cbor_sha256_hex(&projection)
}

pub fn semantic_hash_hex_for_config_bundle(
    bundle: &ConfigBundleV1,
) -> Result<String, ArtifactValidationError> {
    validate_config_bundle(bundle)?;

    let projection = ConfigBundleSemanticProjection::from(bundle);
    canonical_cbor_sha256_hex(&projection)
}

pub fn semantic_cbor_bytes_for_batch_classification_report(
    report: &BatchClassificationReportV1,
) -> Result<Vec<u8>, ArtifactValidationError> {
    semantic_bytes_for_batch_classification_report(report)
}

pub fn semantic_bytes_for_batch_classification_report(
    report: &BatchClassificationReportV1,
) -> Result<Vec<u8>, ArtifactValidationError> {
    validate_batch_classification_report(report)?;

    let projection = BatchClassificationReportSemanticProjection::from(report);
    canonical_cbor_bytes(&projection)
}

pub fn semantic_cbor_bytes_for_decision_bundle(
    bundle: &DecisionBundleV1,
) -> Result<Vec<u8>, ArtifactValidationError> {
    semantic_bytes_for_decision_bundle(bundle)
}

pub fn semantic_cbor_bytes_for_config_bundle(
    bundle: &ConfigBundleV1,
) -> Result<Vec<u8>, ArtifactValidationError> {
    semantic_bytes_for_config_bundle(bundle)
}

pub fn semantic_cbor_bytes_for_recommendation_report(
    report: &RecommendationReportV1,
) -> Result<Vec<u8>, ArtifactValidationError> {
    semantic_bytes_for_recommendation_report(report)
}

pub fn semantic_bytes_for_recommendation_report(
    report: &RecommendationReportV1,
) -> Result<Vec<u8>, ArtifactValidationError> {
    validate_recommendation_report(report)?;

    let projection = RecommendationReportSemanticProjection::from(report);
    canonical_cbor_bytes(&projection)
}

pub fn semantic_bytes_for_decision_bundle(
    bundle: &DecisionBundleV1,
) -> Result<Vec<u8>, ArtifactValidationError> {
    validate_decision_bundle(bundle)?;

    let projection = DecisionBundleSemanticProjection::from(bundle);
    canonical_cbor_bytes(&projection)
}

pub fn semantic_bytes_for_config_bundle(
    bundle: &ConfigBundleV1,
) -> Result<Vec<u8>, ArtifactValidationError> {
    validate_config_bundle(bundle)?;

    let projection = ConfigBundleSemanticProjection::from(bundle);
    canonical_cbor_bytes(&projection)
}

pub fn semantic_projection_json_for_survey(
    survey: &HostSurveyV1,
) -> Result<Value, ArtifactValidationError> {
    semantic_content_json_for_survey(survey)
}

pub fn semantic_content_json_for_survey(
    survey: &HostSurveyV1,
) -> Result<Value, ArtifactValidationError> {
    validate_host_survey(survey)?;
    semantic_projection_json_value(&SurveySemanticProjection::from(survey))
}

pub fn semantic_projection_json_for_contract(
    contract: &HostContractV1,
) -> Result<Value, ArtifactValidationError> {
    semantic_content_json_for_contract(contract)
}

/// Render the contract's semantic content as deterministic JSON for inspection and tests.
pub fn semantic_content_json_for_contract(
    contract: &HostContractV1,
) -> Result<Value, ArtifactValidationError> {
    validate_host_contract(contract)?;
    semantic_projection_json_value(&ContractSemanticProjection::from(contract))
}

pub fn semantic_projection_json_for_service_profile(
    profile: &ServiceProfileV1,
) -> Result<Value, ArtifactValidationError> {
    semantic_content_json_for_service_profile(profile)
}

pub fn semantic_content_json_for_service_profile(
    profile: &ServiceProfileV1,
) -> Result<Value, ArtifactValidationError> {
    validate_service_profile(profile)?;
    semantic_projection_json_value(&ServiceProfileSemanticProjection::from(profile))
}

pub fn semantic_projection_json_for_state(
    state: &HostStateV1,
) -> Result<Value, ArtifactValidationError> {
    semantic_content_json_for_state(state)
}

pub fn semantic_content_json_for_state(
    state: &HostStateV1,
) -> Result<Value, ArtifactValidationError> {
    validate_host_state(state)?;
    semantic_projection_json_value(&StateSemanticProjection::from(state))
}

pub fn semantic_projection_json_for_validation_report(
    report: &ValidationReportV1,
) -> Result<Value, ArtifactValidationError> {
    semantic_content_json_for_validation_report(report)
}

pub fn semantic_content_json_for_validation_report(
    report: &ValidationReportV1,
) -> Result<Value, ArtifactValidationError> {
    validate_validation_report(report)?;
    semantic_projection_json_value(&ValidationReportSemanticProjection::from(report))
}

pub fn semantic_content_json_for_decision_bundle(
    bundle: &DecisionBundleV1,
) -> Result<Value, ArtifactValidationError> {
    validate_decision_bundle(bundle)?;
    semantic_projection_json_value(&DecisionBundleSemanticProjection::from(bundle))
}

pub fn semantic_content_json_for_config_bundle(
    bundle: &ConfigBundleV1,
) -> Result<Value, ArtifactValidationError> {
    validate_config_bundle(bundle)?;
    semantic_projection_json_value(&ConfigBundleSemanticProjection::from(bundle))
}

pub fn semantic_projection_json_for_recommendation_report(
    report: &RecommendationReportV1,
) -> Result<Value, ArtifactValidationError> {
    semantic_content_json_for_recommendation_report(report)
}

pub fn semantic_content_json_for_recommendation_report(
    report: &RecommendationReportV1,
) -> Result<Value, ArtifactValidationError> {
    validate_recommendation_report(report)?;
    semantic_projection_json_value(&RecommendationReportSemanticProjection::from(report))
}

pub fn semantic_projection_json_for_batch_classification_report(
    report: &BatchClassificationReportV1,
) -> Result<Value, ArtifactValidationError> {
    semantic_content_json_for_batch_classification_report(report)
}

pub fn semantic_content_json_for_batch_classification_report(
    report: &BatchClassificationReportV1,
) -> Result<Value, ArtifactValidationError> {
    validate_batch_classification_report(report)?;
    semantic_projection_json_value(&BatchClassificationReportSemanticProjection::from(report))
}

// Semantic projections intentionally drop envelope volatility and keep only the content that
// should affect semantic bytes, hashes, signatures, and diffing.
#[derive(Debug, Clone, PartialEq)]
struct SurveySemanticProjection {
    schema_id: String,
    schema_version: u32,
    survey: CanonicalJsonValue,
}

impl From<&HostSurveyV1> for SurveySemanticProjection {
    fn from(survey: &HostSurveyV1) -> Self {
        Self {
            schema_id: survey.envelope.schema_id.clone(),
            schema_version: survey.envelope.schema_version,
            survey: CanonicalJsonValue::from(&survey.survey),
        }
    }
}

impl Serialize for SurveySemanticProjection {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("schema_id", &self.schema_id)?;
        map.serialize_entry("schema_version", &self.schema_version)?;
        map.serialize_entry("survey", &self.survey)?;
        map.end()
    }
}

// Core-only survey projection used where extension evidence should not affect the comparison.
#[derive(Debug, Clone, PartialEq)]
struct CoreSurveySemanticProjection {
    schema_id: String,
    schema_version: u32,
    core_evidence: CanonicalJsonValue,
}

impl From<&HostSurveyV1> for CoreSurveySemanticProjection {
    fn from(survey: &HostSurveyV1) -> Self {
        let core_evidence = survey
            .survey
            .get("core_evidence")
            .cloned()
            .unwrap_or(Value::Null);
        Self {
            schema_id: survey.envelope.schema_id.clone(),
            schema_version: survey.envelope.schema_version,
            core_evidence: CanonicalJsonValue::from(&core_evidence),
        }
    }
}

impl Serialize for CoreSurveySemanticProjection {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("schema_id", &self.schema_id)?;
        map.serialize_entry("schema_version", &self.schema_version)?;
        map.serialize_entry("core_evidence", &self.core_evidence)?;
        map.end()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct ServiceProfileSemanticProjection {
    schema_id: String,
    schema_version: u32,
    profile: ServiceProfilePayloadSemanticProjection,
}

impl From<&ServiceProfileV1> for ServiceProfileSemanticProjection {
    fn from(profile: &ServiceProfileV1) -> Self {
        Self {
            schema_id: profile.envelope.schema_id.clone(),
            schema_version: profile.envelope.schema_version,
            profile: ServiceProfilePayloadSemanticProjection::from(&profile.profile),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct ServiceProfilePayloadSemanticProjection {
    profile_id: String,
    core_requirements: ServiceRequirementsV1,
    extension_requirements: std::collections::BTreeMap<String, Value>,
    preferences: ServicePreferencesV1,
    exclusions: ServiceExclusionsV1,
    degradation_ladder: Vec<DegradationTierV1>,
    assurance_predicates: Vec<AssurancePredicateV1>,
    assurance_requirements: Vec<ExplicitAssuranceRequirementV1>,
}

impl From<&ServiceProfilePayloadV1> for ServiceProfilePayloadSemanticProjection {
    fn from(profile: &ServiceProfilePayloadV1) -> Self {
        Self {
            profile_id: profile.profile_id.clone(),
            core_requirements: profile.core_requirements.clone(),
            extension_requirements: profile.extension_requirements.clone(),
            preferences: profile.preferences.clone(),
            exclusions: profile.exclusions.clone(),
            degradation_ladder: profile.degradation_ladder.clone(),
            assurance_predicates: profile.assurance_predicates.clone(),
            assurance_requirements: profile.assurance_requirements.clone(),
        }
    }
}

// State semantic identity keeps the payload shape but normalises freshness so observation time
// does not create false drift by itself.
#[derive(Debug, Clone, PartialEq, Serialize)]
struct StateSemanticProjection {
    schema_id: String,
    schema_version: u32,
    state: StatePayloadSemanticProjection,
}

impl From<&HostStateV1> for StateSemanticProjection {
    fn from(state: &HostStateV1) -> Self {
        Self {
            schema_id: state.envelope.schema_id.clone(),
            schema_version: state.envelope.schema_version,
            state: StatePayloadSemanticProjection::from(&state.state),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct StatePayloadSemanticProjection {
    collection_mode: StateCollectionModeV1,
    snapshot_id: String,
    host_alias: String,
    source_ref: String,
    local_identity: Option<crate::artifacts::state_v1::StateLocalIdentityV1>,
    core_state: StateCoreSemanticProjection,
    extension_state: std::collections::BTreeMap<String, Value>,
}

impl From<&HostStatePayloadV1> for StatePayloadSemanticProjection {
    fn from(state: &HostStatePayloadV1) -> Self {
        Self {
            collection_mode: state.collection_mode,
            snapshot_id: state.snapshot_id.clone(),
            host_alias: state.host_alias.clone(),
            source_ref: state.source_ref.clone(),
            local_identity: state.local_identity.clone(),
            core_state: StateCoreSemanticProjection::from(&state.core_state),
            extension_state: state.extension_state.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct StateCoreSemanticProjection {
    collectors: Vec<crate::artifacts::metadata_v1::CollectorMetadataV1>,
    section_metadata: StateSectionMetadataV1,
    freshness: StateFreshnessSemanticProjection,
    resources: HostRuntimeResourcesV1,
    boundaries: HostStateExecutionBoundariesV1,
    topology: HostStateTopologyV1,
    operability: HostStateOperabilityV1,
}

impl From<&crate::artifacts::state_v1::HostStateCoreV1> for StateCoreSemanticProjection {
    fn from(state: &crate::artifacts::state_v1::HostStateCoreV1) -> Self {
        Self {
            collectors: state.collectors.clone(),
            section_metadata: state.section_metadata.clone(),
            freshness: StateFreshnessSemanticProjection::from(&state.freshness),
            resources: state.resources.clone(),
            boundaries: state.boundaries.clone(),
            topology: state.topology.clone(),
            operability: state.operability.clone(),
        }
    }
}

// Only the freshness state contributes to semantic identity; the observed timestamp stays in the
// full artifact for freshness validation and audit purposes.
#[derive(Debug, Clone, PartialEq, Serialize)]
struct StateFreshnessSemanticProjection {
    freshness_state: FreshnessStateV1,
}

impl From<&crate::artifacts::state_v1::StateFreshnessV1> for StateFreshnessSemanticProjection {
    fn from(freshness: &crate::artifacts::state_v1::StateFreshnessV1) -> Self {
        Self {
            freshness_state: freshness.freshness_state,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct ValidationReportSemanticProjection {
    schema_id: String,
    schema_version: u32,
    validation_basis: ValidationBasisV1,
    report: ValidationReportPayloadV1,
}

impl From<&ValidationReportV1> for ValidationReportSemanticProjection {
    fn from(report: &ValidationReportV1) -> Self {
        Self {
            schema_id: report.envelope.schema_id.clone(),
            schema_version: report.envelope.schema_version,
            validation_basis: report.validation_basis.clone(),
            report: report.report.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct DecisionBundleSemanticProjection {
    schema_id: String,
    schema_version: u32,
    bundle_basis: DecisionBundleBasisV1,
    validation_report: ValidationReportSemanticProjection,
    contract: ContractSemanticProjection,
    state: Option<StateSemanticProjection>,
    resolved_config: Option<ResolvedConfigV1>,
    config_bundle: Option<ConfigBundleSemanticProjection>,
    verification_bundle: Option<VerificationBundleV1>,
    recommendation_report: Option<RecommendationReportSemanticProjection>,
}

impl From<&DecisionBundleV1> for DecisionBundleSemanticProjection {
    fn from(bundle: &DecisionBundleV1) -> Self {
        Self {
            schema_id: bundle.envelope.schema_id.clone(),
            schema_version: bundle.envelope.schema_version,
            bundle_basis: bundle.bundle_basis.clone(),
            validation_report: ValidationReportSemanticProjection::from(
                &bundle.bundle.validation_report,
            ),
            contract: ContractSemanticProjection::from(&bundle.bundle.contract),
            state: bundle
                .bundle
                .state
                .as_ref()
                .map(StateSemanticProjection::from),
            resolved_config: bundle.bundle.resolved_config.clone(),
            config_bundle: bundle
                .bundle
                .config_bundle
                .as_ref()
                .map(ConfigBundleSemanticProjection::from),
            verification_bundle: bundle.bundle.verification_bundle.clone(),
            recommendation_report: bundle
                .bundle
                .recommendation_report
                .as_ref()
                .map(RecommendationReportSemanticProjection::from),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct ConfigBundleSemanticProjection {
    schema_id: String,
    schema_version: u32,
    config_bundle_basis: ConfigBundleBasisV1,
    policy: PolicyDocumentV1,
    resolved_config: ResolvedConfigV1,
    service_profile: Option<ServiceProfileSemanticProjection>,
    trust_policy: Option<TrustPolicyV1>,
}

impl From<&ConfigBundleV1> for ConfigBundleSemanticProjection {
    fn from(bundle: &ConfigBundleV1) -> Self {
        Self {
            schema_id: bundle.envelope.schema_id.clone(),
            schema_version: bundle.envelope.schema_version,
            config_bundle_basis: bundle.config_bundle_basis.clone(),
            policy: bundle.config_bundle.policy.clone(),
            resolved_config: bundle.config_bundle.resolved_config.clone(),
            service_profile: bundle
                .config_bundle
                .service_profile
                .as_ref()
                .map(ServiceProfileSemanticProjection::from),
            trust_policy: bundle.config_bundle.trust_policy.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct RecommendationReportSemanticProjection {
    schema_id: String,
    schema_version: u32,
    recommendation_basis: RecommendationBasisV1,
    report: RecommendationReportPayloadSemanticProjection,
}

impl From<&RecommendationReportV1> for RecommendationReportSemanticProjection {
    fn from(report: &RecommendationReportV1) -> Self {
        Self {
            schema_id: report.envelope.schema_id.clone(),
            schema_version: report.envelope.schema_version,
            recommendation_basis: report.recommendation_basis.clone(),
            report: RecommendationReportPayloadSemanticProjection::from(&report.report),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct RecommendationReportPayloadSemanticProjection {
    recommendation_class: Option<String>,
    expected_operating_mode: Option<String>,
    processing_time_band: Option<String>,
    throughput_band: Option<String>,
    confidence: RecommendationConfidenceV1,
    freshness: RecommendationFreshnessSemanticProjection,
    advisory_reason_ids: Vec<String>,
    summary: String,
}

impl From<&RecommendationReportPayloadV1> for RecommendationReportPayloadSemanticProjection {
    fn from(report: &RecommendationReportPayloadV1) -> Self {
        Self {
            recommendation_class: report.recommendation_class.clone(),
            expected_operating_mode: report.expected_operating_mode.clone(),
            processing_time_band: report.processing_time_band.clone(),
            throughput_band: report.throughput_band.clone(),
            confidence: report.confidence,
            freshness: RecommendationFreshnessSemanticProjection::from(&report.freshness),
            advisory_reason_ids: report.advisory_reason_ids.clone(),
            summary: report.summary.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct RecommendationFreshnessSemanticProjection {
    freshness_state: RecommendationFreshnessStateV1,
}

impl From<&crate::artifacts::recommendation_report_v1::RecommendationFreshnessV1>
    for RecommendationFreshnessSemanticProjection
{
    fn from(
        freshness: &crate::artifacts::recommendation_report_v1::RecommendationFreshnessV1,
    ) -> Self {
        Self {
            freshness_state: freshness.freshness_state,
        }
    }
}

// Contract semantic identity includes the derivation basis because policy and selected layers are
// part of what the host is allowed to promise.
#[derive(Debug, Clone, PartialEq)]
struct ContractSemanticProjection {
    schema_id: String,
    schema_version: u32,
    contract_basis: ContractBasisSemanticProjection,
    core_contract: CanonicalJsonValue,
    extension_contract: Option<CanonicalJsonValue>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct BatchClassificationReportSemanticProjection {
    schema_id: String,
    schema_version: u32,
    classification_basis: BatchClassificationBasisSemanticProjection,
    report: BatchClassificationReportPayloadV1,
}

impl From<&BatchClassificationReportV1> for BatchClassificationReportSemanticProjection {
    fn from(report: &BatchClassificationReportV1) -> Self {
        Self {
            schema_id: report.envelope.schema_id.clone(),
            schema_version: report.envelope.schema_version,
            classification_basis: BatchClassificationBasisSemanticProjection::from(
                &report.classification_basis,
            ),
            report: report.report.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct BatchClassificationBasisSemanticProjection {
    validation_mode: crate::artifacts::validation_report_v1::ValidationModeV1,
    max_state_age_seconds: Option<u64>,
    validation_engine_id: String,
    validation_engine_version: String,
    ordered_contracts: Vec<BatchClassificationContractRefSemanticProjection>,
    ordered_service_profiles: Vec<BatchClassificationServiceProfileRefSemanticProjection>,
}

impl From<&BatchClassificationBasisV1> for BatchClassificationBasisSemanticProjection {
    fn from(basis: &BatchClassificationBasisV1) -> Self {
        Self {
            validation_mode: basis.validation_mode,
            max_state_age_seconds: basis.max_state_age_seconds,
            validation_engine_id: basis.validation_engine_id.clone(),
            validation_engine_version: basis.validation_engine_version.clone(),
            ordered_contracts: basis
                .ordered_contracts
                .iter()
                .map(BatchClassificationContractRefSemanticProjection::from)
                .collect(),
            ordered_service_profiles: basis
                .ordered_service_profiles
                .iter()
                .map(BatchClassificationServiceProfileRefSemanticProjection::from)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct BatchClassificationContractRefSemanticProjection {
    artifact_id: String,
    semantic_hash: String,
    matched_state: Option<BatchClassificationStateRefSemanticProjection>,
}

impl From<&BatchClassificationContractRefV1> for BatchClassificationContractRefSemanticProjection {
    fn from(value: &BatchClassificationContractRefV1) -> Self {
        Self {
            artifact_id: value.artifact_id.clone(),
            semantic_hash: value.semantic_hash.clone(),
            matched_state: value
                .matched_state
                .as_ref()
                .map(BatchClassificationStateRefSemanticProjection::from),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct BatchClassificationStateRefSemanticProjection {
    artifact_id: String,
    semantic_hash: String,
    freshness_state: crate::artifacts::state_v1::FreshnessStateV1,
    match_basis: Option<
        crate::artifacts::batch_classification_report_v1::BatchClassificationStateMatchBasisV1,
    >,
}

impl From<&BatchClassificationStateRefV1> for BatchClassificationStateRefSemanticProjection {
    fn from(value: &BatchClassificationStateRefV1) -> Self {
        Self {
            artifact_id: value.artifact_id.clone(),
            semantic_hash: value.semantic_hash.clone(),
            freshness_state: value.freshness_state,
            match_basis: value.match_basis,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct BatchClassificationServiceProfileRefSemanticProjection {
    artifact_id: String,
    semantic_hash: String,
}

impl From<&BatchClassificationServiceProfileRefV1>
    for BatchClassificationServiceProfileRefSemanticProjection
{
    fn from(value: &BatchClassificationServiceProfileRefV1) -> Self {
        Self {
            artifact_id: value.artifact_id.clone(),
            semantic_hash: value.semantic_hash.clone(),
        }
    }
}

impl From<&HostContractV1> for ContractSemanticProjection {
    fn from(contract: &HostContractV1) -> Self {
        Self {
            schema_id: contract.envelope.schema_id.clone(),
            schema_version: contract.envelope.schema_version,
            contract_basis: ContractBasisSemanticProjection {
                core_semantic_basis: ContractSemanticBasisProjection {
                    source_survey_semantic_hash: contract
                        .contract_basis
                        .core_semantic_basis
                        .source_survey_semantic_hash
                        .clone(),
                    policy_semantic_hash: contract
                        .contract_basis
                        .core_semantic_basis
                        .policy_semantic_hash
                        .clone(),
                    derivation_engine_id: contract
                        .contract_basis
                        .core_semantic_basis
                        .derivation_engine_id
                        .clone(),
                    derivation_engine_version: contract
                        .contract_basis
                        .core_semantic_basis
                        .derivation_engine_version
                        .clone(),
                    contract_schema_version: contract
                        .contract_basis
                        .core_semantic_basis
                        .contract_schema_version,
                    selected_policy_layers: contract
                        .contract_basis
                        .core_semantic_basis
                        .selected_policy_layers
                        .clone(),
                },
                extension_basis: contract
                    .contract_basis
                    .extension_basis
                    .as_ref()
                    .map(ContractExtensionBasisProjection::from),
            },
            core_contract: CanonicalJsonValue::from(
                contract
                    .contract
                    .get("core_contract")
                    .unwrap_or(&Value::Null),
            ),
            extension_contract: if contract.contract_basis.extension_basis.is_some() {
                Some(CanonicalJsonValue::from(
                    contract
                        .contract
                        .get("extension_contract")
                        .unwrap_or(&Value::Null),
                ))
            } else {
                None
            },
        }
    }
}

fn canonical_cbor_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, ArtifactValidationError> {
    serde_cbor::to_vec(value).map_err(|error| {
        crate::artifacts::validation_v1::ArtifactValidationError::new(
            crate::artifacts::validation_v1::ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            format!("failed to encode canonical semantic projection as CBOR: {error}"),
        )
    })
}

fn canonical_cbor_sha256_hex<T: Serialize>(value: &T) -> Result<String, ArtifactValidationError> {
    let bytes = canonical_cbor_bytes(value)?;
    let digest = Sha256::digest(bytes);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn semantic_projection_json_value<T: Serialize>(
    value: &T,
) -> Result<Value, ArtifactValidationError> {
    serde_json::to_value(value).map_err(|error| {
        crate::artifacts::validation_v1::ArtifactValidationError::new(
            crate::artifacts::validation_v1::ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            format!("failed to encode semantic projection as JSON value: {error}"),
        )
    })
}

impl Serialize for ContractSemanticProjection {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(5))?;
        map.serialize_entry("schema_id", &self.schema_id)?;
        map.serialize_entry("schema_version", &self.schema_version)?;
        map.serialize_entry("contract_basis", &self.contract_basis)?;
        map.serialize_entry("core_contract", &self.core_contract)?;
        if let Some(extension_contract) = &self.extension_contract {
            map.serialize_entry("extension_contract", extension_contract)?;
        }
        map.end()
    }
}

#[derive(Debug, Clone, PartialEq)]
struct ContractBasisSemanticProjection {
    core_semantic_basis: ContractSemanticBasisProjection,
    extension_basis: Option<ContractExtensionBasisProjection>,
}

impl Serialize for ContractBasisSemanticProjection {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("core_semantic_basis", &self.core_semantic_basis)?;
        if let Some(extension_basis) = &self.extension_basis {
            map.serialize_entry("extension_basis", extension_basis)?;
        }
        map.end()
    }
}

#[derive(Debug, Clone, PartialEq)]
struct ContractSemanticBasisProjection {
    source_survey_semantic_hash: String,
    policy_semantic_hash: String,
    derivation_engine_id: String,
    derivation_engine_version: String,
    contract_schema_version: u32,
    selected_policy_layers: Vec<String>,
}

impl Serialize for ContractSemanticBasisProjection {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(6))?;
        map.serialize_entry(
            "source_survey_semantic_hash",
            &self.source_survey_semantic_hash,
        )?;
        map.serialize_entry("policy_semantic_hash", &self.policy_semantic_hash)?;
        map.serialize_entry("derivation_engine_id", &self.derivation_engine_id)?;
        map.serialize_entry("derivation_engine_version", &self.derivation_engine_version)?;
        map.serialize_entry("contract_schema_version", &self.contract_schema_version)?;
        map.serialize_entry("selected_policy_layers", &self.selected_policy_layers)?;
        map.end()
    }
}

// Extension basis ordering is normalised so registration or activation order does not create
// false semantic drift.
#[derive(Debug, Clone, PartialEq)]
struct ContractExtensionBasisProjection {
    enabled_extension_namespaces: Vec<String>,
    extension_semantic_hashes: Vec<(String, String)>,
}

impl From<&ContractExtensionBasisV1> for ContractExtensionBasisProjection {
    fn from(value: &ContractExtensionBasisV1) -> Self {
        let mut enabled_extension_namespaces = value.enabled_extension_namespaces.clone();
        enabled_extension_namespaces.sort();
        Self {
            enabled_extension_namespaces,
            extension_semantic_hashes: value
                .extension_semantic_hashes
                .iter()
                .map(|(namespace, hash)| (namespace.clone(), hash.clone()))
                .collect(),
        }
    }
}

impl Serialize for ContractExtensionBasisProjection {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry(
            "enabled_extension_namespaces",
            &self.enabled_extension_namespaces,
        )?;
        map.serialize_entry("extension_semantic_hashes", &self.extension_semantic_hashes)?;
        map.end()
    }
}

// Canonical JSON value normalises object ordering before CBOR encoding so equivalent JSON payloads
// converge on one semantic byte representation.
#[derive(Debug, Clone, PartialEq)]
enum CanonicalJsonValue {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<CanonicalJsonValue>),
    Object(Vec<(String, CanonicalJsonValue)>),
}

impl From<&Value> for CanonicalJsonValue {
    fn from(value: &Value) -> Self {
        match value {
            Value::Null => Self::Null,
            Value::Bool(flag) => Self::Bool(*flag),
            Value::Number(number) => Self::Number(number.clone()),
            Value::String(text) => Self::String(text.clone()),
            Value::Array(values) => {
                Self::Array(values.iter().map(CanonicalJsonValue::from).collect())
            }
            Value::Object(map) => Self::Object(canonicalise_object_entries(map)),
        }
    }
}

impl Serialize for CanonicalJsonValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Null => serializer.serialize_unit(),
            Self::Bool(flag) => serializer.serialize_bool(*flag),
            Self::Number(number) => number.serialize(serializer),
            Self::String(text) => serializer.serialize_str(text),
            Self::Array(values) => {
                let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    sequence.serialize_element(value)?;
                }
                sequence.end()
            }
            Self::Object(entries) => {
                let mut map = serializer.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

fn canonicalise_object_entries(map: &Map<String, Value>) -> Vec<(String, CanonicalJsonValue)> {
    let mut entries: Vec<(String, CanonicalJsonValue)> = map
        .iter()
        .map(|(key, value)| (key.clone(), CanonicalJsonValue::from(value)))
        .collect();

    entries.sort_by(|left, right| canonical_cbor_text_key_order(&left.0, &right.0));
    entries
}

fn canonical_cbor_text_key_order(left: &str, right: &str) -> Ordering {
    left.len()
        .cmp(&right.len())
        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
}
