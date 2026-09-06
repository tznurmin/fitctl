// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::artifacts::batch_classification_report_v1::BatchClassificationReportV1;
use crate::artifacts::contract_v1::HostContractV1;
use crate::artifacts::recommendation_report_v1::RecommendationReportV1;
use crate::artifacts::record_v1::ArtifactRecordV1;
use crate::artifacts::state_v1::{HostStateCoreV1, HostStateThermalResourcesV1};
use crate::artifacts::validation_report_v1::ValidationReportV1;
use crate::redact::timestamps_v1::{optional_timestamp, require_timestamp};
use crate::redact::RedactionError;

// Only typed fields retained in supported sharing views are checked here.
pub(super) fn core_times(artifact: &ArtifactRecordV1) -> Result<(), RedactionError> {
    match artifact {
        ArtifactRecordV1::Contract(artifact) => contract_time(artifact)?,
        ArtifactRecordV1::State(artifact) => state_times(&artifact.state.core_state)?,
        ArtifactRecordV1::ThermalEvidence(artifact) => thermal_times(&artifact.thermal_evidence)?,
        ArtifactRecordV1::ValidationReport(artifact) => validation_time(artifact)?,
        ArtifactRecordV1::DecisionBundle(artifact) => {
            let bundle = &artifact.bundle;
            contract_time(&bundle.contract)?;
            validation_time(&bundle.validation_report)?;
            if let Some(state) = &bundle.state {
                state_times(&state.state.core_state)?;
            }
            if let Some(report) = &bundle.recommendation_report {
                recommendation_time(report)?;
            }
            if let Some(verification) = &bundle.verification_bundle {
                require_timestamp(&verification.produced_at, "verification bundle produced_at")?;
                require_timestamp(
                    &verification.verification_report.verified_at,
                    "verification report verified_at",
                )?;
            }
        }
        ArtifactRecordV1::Survey(_)
        | ArtifactRecordV1::ServiceProfile(_)
        | ArtifactRecordV1::ConfigBundle(_) => {}
    }
    Ok(())
}

fn contract_time(artifact: &HostContractV1) -> Result<(), RedactionError> {
    require_timestamp(
        &artifact.contract_basis.derivation_provenance.derived_at,
        "contract derived_at",
    )
}

fn validation_time(artifact: &ValidationReportV1) -> Result<(), RedactionError> {
    optional_timestamp(
        artifact.validation_basis.state_observed_at.as_deref(),
        "validation state_observed_at",
    )
}

pub(super) fn recommendation_time(artifact: &RecommendationReportV1) -> Result<(), RedactionError> {
    require_timestamp(
        &artifact.report.freshness.observed_at,
        "recommendation observed_at",
    )
}

pub(super) fn batch_times(artifact: &BatchClassificationReportV1) -> Result<(), RedactionError> {
    require_timestamp(
        &artifact.classification_basis.validated_at,
        "classification validated_at",
    )?;
    for contract in &artifact.classification_basis.ordered_contracts {
        if let Some(state) = &contract.matched_state {
            require_timestamp(
                &state.observed_at,
                "classification matched state observed_at",
            )?;
        }
    }
    Ok(())
}

fn state_times(core: &HostStateCoreV1) -> Result<(), RedactionError> {
    require_timestamp(&core.freshness.observed_at, "state freshness observed_at")?;
    if let Some(thermal) = &core.thermal_resources {
        thermal_times(thermal)?;
    }
    if let Some(hardware) = &core.hardware_sensor_resources {
        require_timestamp(&hardware.observed_at, "hardware sensors observed_at")?;
        for provider in &hardware.providers {
            require_timestamp(
                &provider.observed_at,
                "hardware sensor provider observed_at",
            )?;
        }
        for reading in &hardware.readings {
            require_timestamp(&reading.observed_at, "hardware sensor reading observed_at")?;
        }
    }
    if let Some(memory) = &core.memory_reliability {
        require_timestamp(&memory.observed_at, "memory reliability observed_at")?;
        for provider in &memory.providers {
            require_timestamp(
                &provider.observed_at,
                "memory reliability provider observed_at",
            )?;
        }
    }
    if let Some(gpu) = &core.gpu_reliability {
        require_timestamp(&gpu.observed_at, "GPU reliability observed_at")?;
        for provider in &gpu.providers {
            require_timestamp(
                &provider.observed_at,
                "GPU reliability provider observed_at",
            )?;
        }
    }
    for path in &core.path_resources.paths {
        optional_timestamp(path.observed_at.as_deref(), "path observed_at")?;
        if let Some(links) = &path.link_capabilities {
            optional_timestamp(
                links.observed_at.as_deref(),
                "path link capabilities observed_at",
            )?;
        }
        if let Some(health) = &path.storage_health {
            optional_timestamp(health.observed_at.as_deref(), "storage health observed_at")?;
        }
    }
    for pair in &core.path_resources.link_pairs {
        optional_timestamp(pair.observed_at.as_deref(), "link pair observed_at")?;
    }
    Ok(())
}

fn thermal_times(thermal: &HostStateThermalResourcesV1) -> Result<(), RedactionError> {
    require_timestamp(&thermal.observed_at, "thermal resources observed_at")?;
    for provider in &thermal.providers {
        require_timestamp(&provider.observed_at, "thermal provider observed_at")?;
    }
    for reading in &thermal.readings {
        require_timestamp(&reading.observed_at, "thermal reading observed_at")?;
    }
    Ok(())
}
