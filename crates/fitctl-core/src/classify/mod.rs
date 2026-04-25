// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Batch host classification over existing contracts and service profiles.
//!
//! This layer reuses the validation engine across a matrix of inputs and emits a typed summary
//! artifact instead of inventing a separate fit-decision model.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::artifacts::batch_classification_report_v1::{
    BatchClassificationBasisV1, BatchClassificationContractRefV1,
    BatchClassificationContractSummaryV1, BatchClassificationReportPayloadV1,
    BatchClassificationReportV1, BatchClassificationRowV1, BatchClassificationServiceProfileRefV1,
    BatchClassificationServiceProfileSummaryV1, BatchClassificationStateMatchBasisV1,
    BatchClassificationStateRefV1,
};
use crate::artifacts::contract_v1::HostContractV1;
use crate::artifacts::envelope_v1::{local_artifact_provenance_v1, ArtifactEnvelopeV1};
use crate::artifacts::schema_ids_v1::{
    is_supported_batch_classification_report_schema_id, BATCH_CLASSIFICATION_REPORT_SCHEMA_ID,
    TOP_LEVEL_ARTIFACT_SCHEMA_VERSION,
};
use crate::artifacts::semantic_hash_v1::{
    semantic_hash_hex_for_contract, semantic_hash_hex_for_service_profile,
    semantic_hash_hex_for_state,
};
use crate::artifacts::service_profile_v1::ServiceProfileV1;
use crate::artifacts::state_v1::HostStateV1;
use crate::artifacts::validation_v1::{
    validate_batch_classification_report, ArtifactValidationErrorCode,
};
use crate::contract::HostContractPayloadV1;
use crate::validate::{
    validate_request_v1, ValidationError, ValidationErrorCode, ValidationModeV1,
    ValidationRequestV1, ValidationVerdictV1,
};

pub const BATCH_CLASSIFICATION_ERROR_MODEL_ID: &str = "fitctl.batch_classification.v2";
pub const BATCH_CLASSIFICATION_ERROR_MODEL_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchClassificationErrorCode {
    BatchInputInvalid,
    BatchSchemaUnsupported,
    BatchArtifactInvalid,
    BatchExecutionFailed,
}

impl BatchClassificationErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BatchInputInvalid => "batch_input_invalid",
            Self::BatchSchemaUnsupported => "batch_schema_unsupported",
            Self::BatchArtifactInvalid => "batch_artifact_invalid",
            Self::BatchExecutionFailed => "batch_execution_failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchClassificationError {
    pub code: BatchClassificationErrorCode,
    pub checkpoint_id: &'static str,
    pub message: String,
    pub error_model_id: &'static str,
    pub error_model_version: u32,
}

impl BatchClassificationError {
    fn new(
        code: BatchClassificationErrorCode,
        checkpoint_id: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            checkpoint_id,
            message: message.into(),
            error_model_id: BATCH_CLASSIFICATION_ERROR_MODEL_ID,
            error_model_version: BATCH_CLASSIFICATION_ERROR_MODEL_VERSION,
        }
    }
}

impl std::fmt::Display for BatchClassificationError {
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

impl std::error::Error for BatchClassificationError {}

#[derive(Debug, Clone, PartialEq)]
pub struct BatchClassificationRequestV1 {
    pub contracts: Vec<HostContractV1>,
    pub service_profiles: Vec<ServiceProfileV1>,
    pub host_states: Vec<HostStateV1>,
    pub validation_mode: ValidationModeV1,
    pub max_state_age_seconds: Option<u64>,
    pub validated_at: String,
}

#[derive(Debug, Clone, PartialEq)]
struct BatchClassificationStateSelectionV1 {
    host_alias: String,
    local_stable_id: Option<String>,
    host_state: HostStateV1,
    report_ref: BatchClassificationStateRefV1,
}

#[derive(Debug, Clone, PartialEq)]
struct BatchClassificationStateIndexV1 {
    by_host_alias: BTreeMap<String, BatchClassificationStateSelectionV1>,
    by_local_stable_id: BTreeMap<String, BatchClassificationStateSelectionV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BatchClassificationContractIdentityV1 {
    host_alias: Option<String>,
    local_stable_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchClassificationExportViewV1 {
    RowsCsv,
    ContractSummaryCsv,
    ServiceProfileSummaryCsv,
}

impl BatchClassificationExportViewV1 {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "rows_csv" => Some(Self::RowsCsv),
            "contract_summary_csv" => Some(Self::ContractSummaryCsv),
            "service_profile_summary_csv" => Some(Self::ServiceProfileSummaryCsv),
            _ => None,
        }
    }
}

pub fn classify_batch_v1(
    request: BatchClassificationRequestV1,
) -> Result<BatchClassificationReportV1, BatchClassificationError> {
    ensure_validated_at(&request.validated_at)?;

    let contracts = sort_unique_contracts(&request.contracts)?;
    let service_profiles = sort_unique_service_profiles(&request.service_profiles)?;
    let host_states = sort_unique_host_states(&request.host_states)?;
    let contract_identities = contracts
        .iter()
        .map(|(artifact_id, contract)| {
            extract_contract_identity(contract).map(|identity| (artifact_id.clone(), identity))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;

    if contracts.is_empty() {
        return Err(BatchClassificationError::new(
            BatchClassificationErrorCode::BatchInputInvalid,
            "batch_request_validate",
            "batch classification requires at least one contract artifact",
        ));
    }
    if service_profiles.is_empty() {
        return Err(BatchClassificationError::new(
            BatchClassificationErrorCode::BatchInputInvalid,
            "batch_request_validate",
            "batch classification requires at least one service-profile artifact",
        ));
    }
    ensure_batch_validation_mode(
        request.validation_mode,
        !host_states.by_host_alias.is_empty(),
        request.max_state_age_seconds,
    )?;

    let mut matched_state_refs = BTreeMap::new();
    let mut matched_states_for_validation = BTreeMap::new();
    let mut used_state_artifact_ids = BTreeSet::new();
    let ordered_contracts = contracts
        .values()
        .map(|contract| {
            let identity = contract_identities
                .get(contract.envelope.artifact_id.as_str())
                .expect("ordered contracts must match the identity map");
            let matched_state = select_host_state_for_contract(contract, identity, &host_states)?
                .map(|state| {
                    used_state_artifact_ids.insert(state.report_ref.artifact_id.clone());
                    matched_states_for_validation.insert(
                        contract.envelope.artifact_id.clone(),
                        state.host_state.clone(),
                    );
                    matched_state_refs.insert(
                        contract.envelope.artifact_id.clone(),
                        state.report_ref.clone(),
                    );
                    state.report_ref
                });
            Ok(BatchClassificationContractRefV1 {
                artifact_id: contract.envelope.artifact_id.clone(),
                semantic_hash: semantic_hash_hex_for_contract(contract).map_err(|error| {
                    BatchClassificationError::new(
                        BatchClassificationErrorCode::BatchExecutionFailed,
                        "batch_validate",
                        error.message,
                    )
                })?,
                host_alias: contract.host_alias.clone(),
                display_name: contract.display_name.clone(),
                short_display_name: contract.short_display_name.clone(),
                matched_state,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    ensure_no_unused_host_states(&host_states, &used_state_artifact_ids)?;

    let ordered_service_profiles = service_profiles
        .values()
        .map(|profile| {
            Ok(BatchClassificationServiceProfileRefV1 {
                artifact_id: profile.envelope.artifact_id.clone(),
                semantic_hash: semantic_hash_hex_for_service_profile(profile).map_err(|error| {
                    BatchClassificationError::new(
                        BatchClassificationErrorCode::BatchExecutionFailed,
                        "batch_validate",
                        error.message,
                    )
                })?,
                display_name: profile.profile.display_name.clone(),
                short_display_name: profile.profile.short_display_name.clone(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut rows = Vec::new();

    for contract_ref in &ordered_contracts {
        let contract = contracts
            .get(contract_ref.artifact_id.as_str())
            .expect("ordered contracts must match the contract map");
        for profile_ref in &ordered_service_profiles {
            let service_profile = service_profiles
                .get(profile_ref.artifact_id.as_str())
                .expect("ordered service profiles must match the profile map");
            let validation_report = validate_request_v1(ValidationRequestV1 {
                contract: contract.clone(),
                service_profile: service_profile.clone(),
                host_state: matched_states_for_validation
                    .get(contract_ref.artifact_id.as_str())
                    .cloned(),
                mode: request.validation_mode,
                validated_at: request.validated_at.clone(),
                notes: Some("batch-classification".to_string()),
                max_state_age_seconds: request.max_state_age_seconds,
            })
            .map_err(map_validation_error)?;

            rows.push(BatchClassificationRowV1 {
                row_id: format!("{}::{}", contract_ref.artifact_id, profile_ref.artifact_id),
                contract_artifact_id: contract_ref.artifact_id.clone(),
                contract_semantic_hash: contract_ref.semantic_hash.clone(),
                service_profile_artifact_id: profile_ref.artifact_id.clone(),
                service_profile_semantic_hash: profile_ref.semantic_hash.clone(),
                verdict: validation_report.report.verdict,
                primary_reason_code: validation_report.report.primary_reason_code,
                selected_degradation_tier: validation_report.report.selected_degradation_tier,
                summary: validation_report.report.summary,
            });
        }
    }

    let report = BatchClassificationReportV1 {
        envelope: ArtifactEnvelopeV1 {
            schema_id: BATCH_CLASSIFICATION_REPORT_SCHEMA_ID.to_string(),
            schema_version: TOP_LEVEL_ARTIFACT_SCHEMA_VERSION,
            artifact_id: build_report_artifact_id(
                &request.validated_at,
                request.validation_mode,
                request.max_state_age_seconds,
                &ordered_contracts,
                &ordered_service_profiles,
            ),
            provenance: local_artifact_provenance_v1(
                format!("classify:{}", request.validation_mode.as_str()),
                request.validated_at.clone(),
                "classify",
                build_correlation_id(
                    request.validation_mode,
                    request.max_state_age_seconds,
                    &ordered_contracts,
                    &ordered_service_profiles,
                ),
            ),
            redaction: None,
            signatures: vec![],
        },
        classification_basis: BatchClassificationBasisV1 {
            validation_mode: request.validation_mode,
            max_state_age_seconds: request.max_state_age_seconds,
            validated_at: request.validated_at,
            validation_engine_id: "fitctl.validate.v1".to_string(),
            validation_engine_version: "1".to_string(),
            ordered_contracts: ordered_contracts.clone(),
            ordered_service_profiles: ordered_service_profiles.clone(),
        },
        report: BatchClassificationReportPayloadV1 {
            rows: rows.clone(),
            contract_summaries: build_contract_summaries(&ordered_contracts, &rows),
            service_profile_summaries: build_service_profile_summaries(
                &ordered_service_profiles,
                &rows,
            ),
        },
    };

    validate_batch_classification_report(&report).map_err(|error| {
        let code = match error.code {
            ArtifactValidationErrorCode::ArtifactSchemaIdInvalid
            | ArtifactValidationErrorCode::ArtifactSchemaVersionInvalid => {
                BatchClassificationErrorCode::BatchSchemaUnsupported
            }
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt
            | ArtifactValidationErrorCode::ContractBasisInvalid => {
                BatchClassificationErrorCode::BatchArtifactInvalid
            }
        };
        BatchClassificationError::new(code, "batch_report_emit", error.message)
    })?;

    Ok(report)
}

pub fn load_batch_classification_report_from_path(
    path: &Path,
) -> Result<BatchClassificationReportV1, BatchClassificationError> {
    let text = fs::read_to_string(path).map_err(|error| {
        BatchClassificationError::new(
            BatchClassificationErrorCode::BatchInputInvalid,
            "batch_input_load",
            format!(
                "failed to read batch classification report {}: {error}",
                path.display()
            ),
        )
    })?;

    let raw: Value = serde_json::from_str(&text).map_err(|error| {
        BatchClassificationError::new(
            BatchClassificationErrorCode::BatchInputInvalid,
            "batch_input_load",
            format!(
                "failed to decode batch classification report {}: {error}",
                path.display()
            ),
        )
    })?;
    load_batch_classification_report_from_value(raw)
}

pub fn load_batch_classification_report_from_value(
    raw: Value,
) -> Result<BatchClassificationReportV1, BatchClassificationError> {
    validate_batch_classification_report_json(&raw)?;

    let report: BatchClassificationReportV1 = serde_json::from_value(raw).map_err(|error| {
        BatchClassificationError::new(
            BatchClassificationErrorCode::BatchInputInvalid,
            "batch_input_load",
            format!("failed to decode typed batch classification report input: {error}"),
        )
    })?;

    validate_batch_classification_report(&report).map_err(|error| {
        let code = match error.code {
            ArtifactValidationErrorCode::ArtifactSchemaIdInvalid
            | ArtifactValidationErrorCode::ArtifactSchemaVersionInvalid => {
                BatchClassificationErrorCode::BatchSchemaUnsupported
            }
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt
            | ArtifactValidationErrorCode::ContractBasisInvalid => {
                BatchClassificationErrorCode::BatchArtifactInvalid
            }
        };
        BatchClassificationError::new(code, "batch_report_emit", error.message)
    })?;

    Ok(report)
}

pub fn render_batch_classification_export_view(
    report: &BatchClassificationReportV1,
    view: BatchClassificationExportViewV1,
) -> String {
    match view {
        BatchClassificationExportViewV1::RowsCsv => render_rows_csv(&report.report.rows),
        BatchClassificationExportViewV1::ContractSummaryCsv => {
            render_contract_summaries_csv(&report.report.contract_summaries)
        }
        BatchClassificationExportViewV1::ServiceProfileSummaryCsv => {
            render_service_profile_summaries_csv(&report.report.service_profile_summaries)
        }
    }
}

fn render_rows_csv(rows: &[BatchClassificationRowV1]) -> String {
    let mut output = String::from(
        "row_id,contract_artifact_id,service_profile_artifact_id,verdict,primary_reason_code,selected_degradation_tier,summary\n",
    );
    for row in rows {
        push_csv_row(
            &mut output,
            &[
                row.row_id.as_str(),
                row.contract_artifact_id.as_str(),
                row.service_profile_artifact_id.as_str(),
                row.verdict.as_str(),
                row.primary_reason_code.as_str(),
                row.selected_degradation_tier.as_deref().unwrap_or(""),
                row.summary.as_str(),
            ],
        );
    }
    output
}

fn render_contract_summaries_csv(summaries: &[BatchClassificationContractSummaryV1]) -> String {
    let mut output = String::from(
        "contract_artifact_id,fit_profile_ids,degraded_profile_ids,unfit_profile_ids,indeterminate_profile_ids\n",
    );
    for summary in summaries {
        push_csv_row(
            &mut output,
            &[
                summary.contract_artifact_id.as_str(),
                &summary.fit_profile_ids.join("|"),
                &summary.degraded_profile_ids.join("|"),
                &summary.unfit_profile_ids.join("|"),
                &summary.indeterminate_profile_ids.join("|"),
            ],
        );
    }
    output
}

fn render_service_profile_summaries_csv(
    summaries: &[BatchClassificationServiceProfileSummaryV1],
) -> String {
    let mut output = String::from(
        "service_profile_artifact_id,fit_contract_ids,degraded_contract_ids,unfit_contract_ids,indeterminate_contract_ids\n",
    );
    for summary in summaries {
        push_csv_row(
            &mut output,
            &[
                summary.service_profile_artifact_id.as_str(),
                &summary.fit_contract_ids.join("|"),
                &summary.degraded_contract_ids.join("|"),
                &summary.unfit_contract_ids.join("|"),
                &summary.indeterminate_contract_ids.join("|"),
            ],
        );
    }
    output
}

fn push_csv_row(output: &mut String, fields: &[&str]) {
    let mut first = true;
    for field in fields {
        if !first {
            output.push(',');
        }
        first = false;
        push_csv_field(output, field);
    }
    output.push('\n');
}

fn push_csv_field(output: &mut String, field: &str) {
    let needs_quotes = field.contains(',') || field.contains('"') || field.contains('\n');
    if !needs_quotes {
        output.push_str(field);
        return;
    }

    output.push('"');
    for ch in field.chars() {
        if ch == '"' {
            output.push('"');
        }
        output.push(ch);
    }
    output.push('"');
}

fn build_contract_summaries(
    ordered_contracts: &[BatchClassificationContractRefV1],
    rows: &[BatchClassificationRowV1],
) -> Vec<BatchClassificationContractSummaryV1> {
    ordered_contracts
        .iter()
        .map(|contract| {
            let mut fit_profile_ids = Vec::new();
            let mut degraded_profile_ids = Vec::new();
            let mut unfit_profile_ids = Vec::new();
            let mut indeterminate_profile_ids = Vec::new();

            for row in rows
                .iter()
                .filter(|row| row.contract_artifact_id == contract.artifact_id)
            {
                match row.verdict {
                    ValidationVerdictV1::Fit => {
                        fit_profile_ids.push(row.service_profile_artifact_id.clone())
                    }
                    ValidationVerdictV1::FitWithDegradation => {
                        degraded_profile_ids.push(row.service_profile_artifact_id.clone())
                    }
                    ValidationVerdictV1::Unfit => {
                        unfit_profile_ids.push(row.service_profile_artifact_id.clone())
                    }
                    ValidationVerdictV1::Indeterminate => {
                        indeterminate_profile_ids.push(row.service_profile_artifact_id.clone())
                    }
                }
            }

            BatchClassificationContractSummaryV1 {
                contract_artifact_id: contract.artifact_id.clone(),
                fit_profile_ids,
                degraded_profile_ids,
                unfit_profile_ids,
                indeterminate_profile_ids,
            }
        })
        .collect()
}

fn build_service_profile_summaries(
    ordered_service_profiles: &[BatchClassificationServiceProfileRefV1],
    rows: &[BatchClassificationRowV1],
) -> Vec<BatchClassificationServiceProfileSummaryV1> {
    ordered_service_profiles
        .iter()
        .map(|profile| {
            let mut fit_contract_ids = Vec::new();
            let mut degraded_contract_ids = Vec::new();
            let mut unfit_contract_ids = Vec::new();
            let mut indeterminate_contract_ids = Vec::new();

            for row in rows
                .iter()
                .filter(|row| row.service_profile_artifact_id == profile.artifact_id)
            {
                match row.verdict {
                    ValidationVerdictV1::Fit => {
                        fit_contract_ids.push(row.contract_artifact_id.clone())
                    }
                    ValidationVerdictV1::FitWithDegradation => {
                        degraded_contract_ids.push(row.contract_artifact_id.clone())
                    }
                    ValidationVerdictV1::Unfit => {
                        unfit_contract_ids.push(row.contract_artifact_id.clone())
                    }
                    ValidationVerdictV1::Indeterminate => {
                        indeterminate_contract_ids.push(row.contract_artifact_id.clone())
                    }
                }
            }

            BatchClassificationServiceProfileSummaryV1 {
                service_profile_artifact_id: profile.artifact_id.clone(),
                fit_contract_ids,
                degraded_contract_ids,
                unfit_contract_ids,
                indeterminate_contract_ids,
            }
        })
        .collect()
}

fn sort_unique_contracts(
    contracts: &[HostContractV1],
) -> Result<BTreeMap<String, HostContractV1>, BatchClassificationError> {
    let mut ordered = BTreeMap::new();

    for contract in contracts {
        let artifact_id = contract.envelope.artifact_id.clone();
        if artifact_id.trim().is_empty() {
            return Err(BatchClassificationError::new(
                BatchClassificationErrorCode::BatchInputInvalid,
                "batch_contract_select",
                "contract artifact ids must be non-blank for batch classification",
            ));
        }
        if ordered
            .insert(artifact_id.clone(), contract.clone())
            .is_some()
        {
            return Err(BatchClassificationError::new(
                BatchClassificationErrorCode::BatchInputInvalid,
                "batch_contract_select",
                format!("duplicate contract artifact id {artifact_id} is not allowed"),
            ));
        }
    }

    Ok(ordered)
}

fn sort_unique_service_profiles(
    service_profiles: &[ServiceProfileV1],
) -> Result<BTreeMap<String, ServiceProfileV1>, BatchClassificationError> {
    let mut ordered = BTreeMap::new();

    for service_profile in service_profiles {
        let artifact_id = service_profile.envelope.artifact_id.clone();
        if artifact_id.trim().is_empty() {
            return Err(BatchClassificationError::new(
                BatchClassificationErrorCode::BatchInputInvalid,
                "batch_profile_select",
                "service-profile artifact ids must be non-blank for batch classification",
            ));
        }
        if ordered
            .insert(artifact_id.clone(), service_profile.clone())
            .is_some()
        {
            return Err(BatchClassificationError::new(
                BatchClassificationErrorCode::BatchInputInvalid,
                "batch_profile_select",
                format!("duplicate service-profile artifact id {artifact_id} is not allowed"),
            ));
        }
    }

    Ok(ordered)
}

fn sort_unique_host_states(
    host_states: &[HostStateV1],
) -> Result<BatchClassificationStateIndexV1, BatchClassificationError> {
    let mut by_host_alias = BTreeMap::new();
    let mut by_local_stable_id = BTreeMap::new();

    for host_state in host_states {
        let artifact_id = host_state.envelope.artifact_id.clone();
        if artifact_id.trim().is_empty() {
            return Err(BatchClassificationError::new(
                BatchClassificationErrorCode::BatchInputInvalid,
                "batch_state_select",
                "host-state artifact ids must be non-blank for batch classification",
            ));
        }
        let host_alias = host_state.state.host_alias.clone();
        if host_alias.trim().is_empty() {
            return Err(BatchClassificationError::new(
                BatchClassificationErrorCode::BatchInputInvalid,
                "batch_state_select",
                "host-state host_alias must be non-blank for batch classification",
            ));
        }
        let report_ref = BatchClassificationStateRefV1 {
            artifact_id,
            semantic_hash: semantic_hash_hex_for_state(host_state).map_err(|error| {
                BatchClassificationError::new(
                    BatchClassificationErrorCode::BatchExecutionFailed,
                    "batch_state_select",
                    error.message,
                )
            })?,
            observed_at: host_state.state.core_state.freshness.observed_at.clone(),
            freshness_state: host_state.state.core_state.freshness.freshness_state,
            match_basis: None,
        };
        let selection = BatchClassificationStateSelectionV1 {
            host_alias: host_alias.clone(),
            local_stable_id: host_state
                .state
                .local_identity
                .as_ref()
                .map(|identity| identity.local_stable_id.clone()),
            host_state: host_state.clone(),
            report_ref,
        };
        if by_host_alias
            .insert(host_alias.clone(), selection.clone())
            .is_some()
        {
            return Err(BatchClassificationError::new(
                BatchClassificationErrorCode::BatchInputInvalid,
                "batch_state_select",
                format!("duplicate host-state host_alias {host_alias} is not allowed"),
            ));
        }
        if let Some(local_stable_id) = selection.local_stable_id.as_ref() {
            if by_local_stable_id
                .insert(local_stable_id.clone(), selection.clone())
                .is_some()
            {
                return Err(BatchClassificationError::new(
                    BatchClassificationErrorCode::BatchInputInvalid,
                    "batch_state_select",
                    format!(
                        "duplicate host-state local_stable_id {local_stable_id} is not allowed"
                    ),
                ));
            }
        }
    }

    Ok(BatchClassificationStateIndexV1 {
        by_host_alias,
        by_local_stable_id,
    })
}

fn ensure_batch_validation_mode(
    validation_mode: ValidationModeV1,
    has_host_states: bool,
    max_state_age_seconds: Option<u64>,
) -> Result<(), BatchClassificationError> {
    match validation_mode {
        ValidationModeV1::ContractOnly => {
            if has_host_states {
                return Err(BatchClassificationError::new(
                    BatchClassificationErrorCode::BatchInputInvalid,
                    "batch_request_validate",
                    "contract_only batch classification must not accept host-state inputs",
                ));
            }
            if max_state_age_seconds.is_some() {
                return Err(BatchClassificationError::new(
                    BatchClassificationErrorCode::BatchInputInvalid,
                    "batch_request_validate",
                    "contract_only batch classification must not accept max_state_age_seconds",
                ));
            }
        }
        ValidationModeV1::StateAdvisory | ValidationModeV1::StateRequired => {
            if max_state_age_seconds.is_some() && !has_host_states {
                return Err(BatchClassificationError::new(
                    BatchClassificationErrorCode::BatchInputInvalid,
                    "batch_request_validate",
                    "batch classification max_state_age_seconds requires at least one host-state input",
                ));
            }
        }
        ValidationModeV1::StateAware => {
            return Err(BatchClassificationError::new(
                BatchClassificationErrorCode::BatchInputInvalid,
                "batch_request_validate",
                "batch classification supports contract_only, state_advisory, and state_required only",
            ));
        }
    }

    Ok(())
}

fn ensure_no_unused_host_states(
    host_states: &BatchClassificationStateIndexV1,
    used_state_artifact_ids: &BTreeSet<String>,
) -> Result<(), BatchClassificationError> {
    if let Some(unused_alias) = host_states
        .by_host_alias
        .iter()
        .find(|(_, state)| !used_state_artifact_ids.contains(&state.report_ref.artifact_id))
        .map(|(alias, _)| alias)
    {
        return Err(BatchClassificationError::new(
            BatchClassificationErrorCode::BatchInputInvalid,
            "batch_state_map",
            format!(
                "host-state input for host_alias {unused_alias} does not match any batch contract"
            ),
        ));
    }

    Ok(())
}

fn extract_contract_identity(
    contract: &HostContractV1,
) -> Result<BatchClassificationContractIdentityV1, BatchClassificationError> {
    let payload: HostContractPayloadV1 = serde_json::from_value(contract.contract.clone())
        .map_err(|error| {
            BatchClassificationError::new(
                BatchClassificationErrorCode::BatchInputInvalid,
                "batch_contract_select",
                format!(
                    "failed to decode host contract payload {}: {error}",
                    contract.envelope.artifact_id
                ),
            )
        })?;
    let local_stable_id = payload
        .core_contract
        .identity_summary
        .local_stable_id
        .trim()
        .to_string();
    Ok(BatchClassificationContractIdentityV1 {
        host_alias: contract.host_alias.clone(),
        local_stable_id: (!local_stable_id.is_empty()).then_some(local_stable_id),
    })
}

fn select_host_state_for_contract(
    contract: &HostContractV1,
    identity: &BatchClassificationContractIdentityV1,
    host_states: &BatchClassificationStateIndexV1,
) -> Result<Option<BatchClassificationStateSelectionV1>, BatchClassificationError> {
    let alias_state = identity
        .host_alias
        .as_deref()
        .and_then(|alias| host_states.by_host_alias.get(alias));

    if let Some(local_stable_id) = identity.local_stable_id.as_deref() {
        if let Some(state) = host_states.by_local_stable_id.get(local_stable_id) {
            let mut matched = state.clone();
            matched.report_ref.match_basis =
                Some(BatchClassificationStateMatchBasisV1::LocalStableId);
            return Ok(Some(matched));
        }
    }

    if let Some(state) = alias_state {
        if state.local_stable_id.is_some() {
            return Err(BatchClassificationError::new(
                BatchClassificationErrorCode::BatchInputInvalid,
                "batch_state_map",
                format!(
                    "host-state {} carries local identity that does not match contract {}",
                    state.report_ref.artifact_id, contract.envelope.artifact_id
                ),
            ));
        }

        let mut matched = state.clone();
        matched.report_ref.match_basis =
            Some(BatchClassificationStateMatchBasisV1::HostAliasFallback);
        return Ok(Some(matched));
    }

    Ok(None)
}

fn ensure_validated_at(validated_at: &str) -> Result<(), BatchClassificationError> {
    if validated_at.trim().is_empty() {
        return Err(BatchClassificationError::new(
            BatchClassificationErrorCode::BatchInputInvalid,
            "batch_request_validate",
            "batch classification requires a non-blank validated-at timestamp",
        ));
    }
    parse_timestamp_seconds(validated_at).map(|_| ())
}

fn parse_timestamp_seconds(value: &str) -> Result<i64, BatchClassificationError> {
    if let Some(rest) = value.strip_prefix("unix:") {
        let seconds = rest.parse::<i64>().map_err(|_| {
            BatchClassificationError::new(
                BatchClassificationErrorCode::BatchInputInvalid,
                "batch_request_validate",
                "batch classification validated-at must be RFC3339 UTC or unix:<seconds>",
            )
        })?;
        if seconds < 0 {
            return Err(BatchClassificationError::new(
                BatchClassificationErrorCode::BatchInputInvalid,
                "batch_request_validate",
                "batch classification unix timestamps must be non-negative",
            ));
        }
        return Ok(seconds);
    }

    parse_rfc3339_utc_seconds(value)
}

fn parse_rfc3339_utc_seconds(value: &str) -> Result<i64, BatchClassificationError> {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return Err(BatchClassificationError::new(
            BatchClassificationErrorCode::BatchInputInvalid,
            "batch_request_validate",
            "batch classification validated-at must be RFC3339 UTC or unix:<seconds>",
        ));
    }

    let year = value[0..4]
        .parse::<i32>()
        .map_err(|_| invalid_timestamp_error())?;
    let month = value[5..7]
        .parse::<u32>()
        .map_err(|_| invalid_timestamp_error())?;
    let day = value[8..10]
        .parse::<u32>()
        .map_err(|_| invalid_timestamp_error())?;
    let hour = value[11..13]
        .parse::<u32>()
        .map_err(|_| invalid_timestamp_error())?;
    let minute = value[14..16]
        .parse::<u32>()
        .map_err(|_| invalid_timestamp_error())?;
    let second = value[17..19]
        .parse::<u32>()
        .map_err(|_| invalid_timestamp_error())?;

    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(invalid_timestamp_error());
    }

    let days = days_from_civil(year, month, day);
    Ok(days * 86_400 + i64::from(hour * 3_600 + minute * 60 + second))
}

fn invalid_timestamp_error() -> BatchClassificationError {
    BatchClassificationError::new(
        BatchClassificationErrorCode::BatchInputInvalid,
        "batch_request_validate",
        "batch classification validated-at must be RFC3339 UTC or unix:<seconds>",
    )
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = i64::from(year) - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day = i64::from(day);
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn build_report_artifact_id(
    validated_at: &str,
    validation_mode: ValidationModeV1,
    max_state_age_seconds: Option<u64>,
    ordered_contracts: &[BatchClassificationContractRefV1],
    ordered_service_profiles: &[BatchClassificationServiceProfileRefV1],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(validated_at.as_bytes());
    hasher.update(validation_mode.as_str().as_bytes());
    if let Some(max_state_age_seconds) = max_state_age_seconds {
        hasher.update(max_state_age_seconds.to_le_bytes());
    }
    for contract in ordered_contracts {
        hasher.update(contract.artifact_id.as_bytes());
        hasher.update(contract.semantic_hash.as_bytes());
        if let Some(matched_state) = contract.matched_state.as_ref() {
            hasher.update(matched_state.artifact_id.as_bytes());
            hasher.update(matched_state.semantic_hash.as_bytes());
            hasher.update(matched_state.observed_at.as_bytes());
            hasher.update(matched_state.freshness_state.as_str().as_bytes());
            if let Some(match_basis) = matched_state.match_basis {
                hasher.update(match_basis.as_str().as_bytes());
            }
        }
    }
    for profile in ordered_service_profiles {
        hasher.update(profile.artifact_id.as_bytes());
        hasher.update(profile.semantic_hash.as_bytes());
    }
    let digest = hasher.finalize();
    let hex = digest
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("batch-classification-{hex}")
}

fn build_correlation_id(
    validation_mode: ValidationModeV1,
    max_state_age_seconds: Option<u64>,
    ordered_contracts: &[BatchClassificationContractRefV1],
    ordered_service_profiles: &[BatchClassificationServiceProfileRefV1],
) -> String {
    let state_artifact_ids = ordered_contracts
        .iter()
        .filter_map(|value| {
            value.matched_state.as_ref().map(|state| {
                let basis = state
                    .match_basis
                    .map(|value| value.as_str())
                    .unwrap_or("<none>");
                format!("{}:{basis}", state.artifact_id)
            })
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "mode:{};max_state_age:{};contracts:{};profiles:{};states:{}",
        validation_mode.as_str(),
        max_state_age_seconds
            .map(|value| value.to_string())
            .unwrap_or_else(|| "<none>".to_string()),
        ordered_contracts
            .iter()
            .map(|value| value.artifact_id.as_str())
            .collect::<Vec<_>>()
            .join(","),
        ordered_service_profiles
            .iter()
            .map(|value| value.artifact_id.as_str())
            .collect::<Vec<_>>()
            .join(","),
        if state_artifact_ids.is_empty() {
            "<none>".to_string()
        } else {
            state_artifact_ids
        }
    )
}

fn map_validation_error(error: ValidationError) -> BatchClassificationError {
    let code = match error.code {
        ValidationErrorCode::ValidationInputInvalid
        | ValidationErrorCode::ContractArtifactInvalid
        | ValidationErrorCode::ServiceProfileArtifactInvalid
        | ValidationErrorCode::StateArtifactInvalid
        | ValidationErrorCode::ValidationModeUnsupported => {
            BatchClassificationErrorCode::BatchInputInvalid
        }
        ValidationErrorCode::ValidationReportInvalid
        | ValidationErrorCode::ValidationExecutionFailed => {
            BatchClassificationErrorCode::BatchExecutionFailed
        }
    };
    BatchClassificationError::new(code, "batch_validate", error.message)
}

fn validate_batch_classification_report_json(raw: &Value) -> Result<(), BatchClassificationError> {
    let root = raw.as_object().ok_or_else(|| {
        BatchClassificationError::new(
            BatchClassificationErrorCode::BatchInputInvalid,
            "batch_input_load",
            "batch classification report must decode to a JSON object",
        )
    })?;

    reject_unknown_keys(root, &["envelope", "classification_basis", "report"])?;
    reject_explicit_nulls(
        root,
        &["envelope", "classification_basis", "report"],
        "batch classification report field",
    )?;

    let envelope = require_object(root, "envelope", "batch classification envelope")?;
    reject_unknown_keys(
        envelope,
        &[
            "schema_id",
            "schema_version",
            "artifact_id",
            "provenance",
            "redaction",
            "signatures",
        ],
    )?;
    reject_explicit_nulls(
        envelope,
        &[
            "schema_id",
            "schema_version",
            "artifact_id",
            "provenance",
            "signatures",
        ],
        "batch classification envelope field",
    )?;
    let schema_id = envelope
        .get("schema_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            BatchClassificationError::new(
                BatchClassificationErrorCode::BatchInputInvalid,
                "batch_input_load",
                "batch classification envelope schema_id must be a non-null string",
            )
        })?;
    if !is_supported_batch_classification_report_schema_id(schema_id) {
        return Err(BatchClassificationError::new(
            BatchClassificationErrorCode::BatchSchemaUnsupported,
            "batch_input_load",
            format!("unsupported batch classification schema id {schema_id}"),
        ));
    }

    let provenance = require_object(envelope, "provenance", "batch classification provenance")?;
    reject_unknown_keys(
        provenance,
        &[
            "source",
            "collected_at",
            "fitctl_version",
            "fitctl_vcs_revision",
            "fitctl_vcs_describe",
            "fitctl_build_dirty",
            "command_name",
            "correlation_id",
        ],
    )?;
    reject_explicit_nulls(
        provenance,
        &["source", "collected_at"],
        "batch classification provenance field",
    )?;

    let basis = require_object(root, "classification_basis", "batch classification basis")?;
    reject_explicit_nulls(
        basis,
        &[
            "validation_mode",
            "validated_at",
            "validation_engine_id",
            "validation_engine_version",
            "max_state_age_seconds",
            "ordered_contracts",
            "ordered_service_profiles",
        ],
        "batch classification basis field",
    )?;

    let report = require_object(root, "report", "batch classification report payload")?;
    reject_explicit_nulls(
        report,
        &["rows", "contract_summaries", "service_profile_summaries"],
        "batch classification report field",
    )?;

    Ok(())
}

fn require_object<'a>(
    value: &'a Map<String, Value>,
    key: &'static str,
    label: &'static str,
) -> Result<&'a Map<String, Value>, BatchClassificationError> {
    value.get(key).and_then(Value::as_object).ok_or_else(|| {
        BatchClassificationError::new(
            BatchClassificationErrorCode::BatchInputInvalid,
            "batch_input_load",
            format!("{label} must be a non-null object"),
        )
    })
}

fn reject_unknown_keys(
    map: &Map<String, Value>,
    allowed_keys: &[&str],
) -> Result<(), BatchClassificationError> {
    if let Some(key) = map.keys().find(|key| !allowed_keys.contains(&key.as_str())) {
        return Err(BatchClassificationError::new(
            BatchClassificationErrorCode::BatchInputInvalid,
            "batch_input_load",
            format!("batch classification report contains unsupported field {key}"),
        ));
    }

    Ok(())
}

fn reject_explicit_nulls(
    map: &Map<String, Value>,
    keys: &[&str],
    label: &'static str,
) -> Result<(), BatchClassificationError> {
    if let Some(key) = keys
        .iter()
        .find(|key| map.get(**key).is_some_and(Value::is_null))
    {
        return Err(BatchClassificationError::new(
            BatchClassificationErrorCode::BatchInputInvalid,
            "batch_input_load",
            format!("{label} {key} must not be null"),
        ));
    }

    Ok(())
}

pub fn batch_classification_report_schema_id() -> &'static str {
    BATCH_CLASSIFICATION_REPORT_SCHEMA_ID
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::validation_report_v1::{ValidationReasonCodeV1, ValidationVerdictV1};

    #[test]
    fn export_view_parser_accepts_supported_values_only() {
        assert_eq!(
            BatchClassificationExportViewV1::parse("rows_csv"),
            Some(BatchClassificationExportViewV1::RowsCsv)
        );
        assert_eq!(
            BatchClassificationExportViewV1::parse("contract_summary_csv"),
            Some(BatchClassificationExportViewV1::ContractSummaryCsv)
        );
        assert_eq!(
            BatchClassificationExportViewV1::parse("service_profile_summary_csv"),
            Some(BatchClassificationExportViewV1::ServiceProfileSummaryCsv)
        );
        assert_eq!(BatchClassificationExportViewV1::parse("markdown"), None);
    }

    #[test]
    fn rows_csv_export_quotes_commas_and_quotes() {
        let csv = render_rows_csv(&[BatchClassificationRowV1 {
            row_id: "row-1".to_string(),
            contract_artifact_id: "contract-1".to_string(),
            contract_semantic_hash: "hash-left".to_string(),
            service_profile_artifact_id: "profile-1".to_string(),
            service_profile_semantic_hash: "hash-right".to_string(),
            verdict: ValidationVerdictV1::FitWithDegradation,
            primary_reason_code: ValidationReasonCodeV1::DegradationPathRequired,
            selected_degradation_tier: Some("general_compute".to_string()),
            summary: "prefers \"gpu\", falls back".to_string(),
        }]);

        assert!(csv.contains("row_id,contract_artifact_id,service_profile_artifact_id"));
        assert!(csv.contains("\"prefers \"\"gpu\"\", falls back\""));
    }
}
