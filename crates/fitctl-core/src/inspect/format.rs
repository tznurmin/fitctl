// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Formatting helpers shared by the inspect renderer.

use std::collections::BTreeMap;

use super::*;
use crate::artifacts::batch_classification_report_v1::{
    BatchClassificationContractRefV1, BatchClassificationReportV1, BatchClassificationRowV1,
    BatchClassificationServiceProfileRefV1,
};
use crate::artifacts::state_v1::FreshnessStateV1;
use crate::artifacts::validation_report_v1::{ValidationBasisV1, ValidationReportPayloadV1};
use crate::survey::{IpAddressFamilyV1, StaticOperabilityV1};

pub(super) fn push_line(
    output: &mut String,
    label: &str,
    value: impl Into<String>,
) -> Result<(), InspectError> {
    writeln!(output, "  {label}: {}", value.into()).map_err(|error| {
        InspectError::new(
            InspectErrorCode::InspectRenderFailed,
            "inspect_render",
            format!("failed to render summary line: {error}"),
        )
    })
}

pub(super) fn format_survey_field<T>(
    field: &SurveyFieldV1<T>,
    value_formatter: impl Fn(&T) -> String,
) -> String {
    let value = field
        .value
        .as_ref()
        .map(value_formatter)
        .unwrap_or_else(|| "<none>".to_string());
    format!(
        "{}; {value}",
        format_observation_surface(&field.state, field.limitation_reason.as_ref())
    )
}

pub(super) fn format_state_field<T>(
    field: &StateFieldV1<T>,
    value_formatter: impl Fn(&T) -> String,
) -> String {
    let value = field
        .value
        .as_ref()
        .map(value_formatter)
        .unwrap_or_else(|| "<none>".to_string());
    format!(
        "{}; {value}",
        format_observation_surface(&field.state, field.limitation_reason.as_ref())
    )
}

pub(super) fn format_cpu_details_for_inspect(
    value: &CpuDetailsV1,
    options: InspectRenderOptionsV1,
) -> String {
    let mut parts = vec![
        value.architecture.clone(),
        format!("{} logical cores", value.logical_cores),
    ];

    if let Some(physical_cores) = value.physical_cores {
        parts.push(format!("{physical_cores} physical cores"));
    }
    if let Some(threads_per_core) = value.threads_per_core {
        parts.push(format!("{threads_per_core} threads/core"));
    }
    if let Some(cache_summary) = value.cache_summary.as_ref() {
        parts.push(format_cpu_cache_summary_for_inspect(cache_summary));
    }
    if options.verbose {
        if let Some(model_basis) = value.model_basis {
            parts.push(format!("model basis {}", model_basis.as_str()));
        }
    }
    if options.verbose {
        parts.push(format!(
            "flags {}",
            if value.feature_flags.is_empty() {
                "<none>".to_string()
            } else {
                value.feature_flags.join(", ")
            }
        ));
    } else if !value.feature_flags.is_empty() {
        parts.push(format!("{} flags", value.feature_flags.len()));
    }

    parts.push(value.model.clone());
    parts.join("; ")
}

pub(super) fn format_cpu_cache_summary_for_inspect(summary: &CpuCacheSummaryV1) -> String {
    let mut parts = Vec::new();
    if let Some(value) = summary.l1_data_bytes {
        parts.push(format!("L1d {}", format_bytes_compact(value)));
    }
    if let Some(value) = summary.l1_instruction_bytes {
        parts.push(format!("L1i {}", format_bytes_compact(value)));
    }
    if let Some(value) = summary.l2_bytes {
        parts.push(format!("L2 {}", format_bytes_compact(value)));
    }
    if let Some(value) = summary.l3_bytes {
        parts.push(format!("L3 {}", format_bytes_compact(value)));
    }

    if parts.is_empty() {
        "cache summary <none>".to_string()
    } else {
        match summary.summary_basis {
            CpuCacheSummaryBasisV1::RepresentativeInstanceSizes => {
                format!("cache instances {}", parts.join(", "))
            }
        }
    }
}

pub(super) fn format_accelerator_details_for_inspect(
    value: &AcceleratorDetailsV1,
    options: InspectRenderOptionsV1,
) -> String {
    let accelerator_numa_nodes = value
        .devices
        .iter()
        .filter_map(|device| device.numa_node)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let accelerators_with_known_numa_node = u32::try_from(
        value
            .devices
            .iter()
            .filter(|device| device.numa_node.is_some())
            .count(),
    )
    .ok()
    .filter(|count| *count > 0);
    let mut kinds = value
        .devices
        .iter()
        .map(|device| device.kind.as_str().to_string())
        .collect::<Vec<_>>();
    kinds.sort();
    kinds.dedup();
    let mut vendors = value
        .devices
        .iter()
        .filter_map(|device| device.vendor.clone())
        .collect::<Vec<_>>();
    vendors.sort();
    vendors.dedup();
    let mut families = value
        .devices
        .iter()
        .filter_map(|device| device.family.clone())
        .collect::<Vec<_>>();
    families.sort();
    families.dedup();
    let mut models = value
        .devices
        .iter()
        .filter_map(|device| device.model.clone())
        .collect::<Vec<_>>();
    models.sort();
    models.dedup();
    let mut drivers = value
        .devices
        .iter()
        .filter_map(|device| device.driver.clone())
        .collect::<Vec<_>>();
    drivers.sort();
    drivers.dedup();
    let integrated_devices = value
        .devices
        .iter()
        .filter(|device| {
            device.integration == Some(crate::survey::AcceleratorIntegrationV1::Integrated)
        })
        .count();
    let max_memory_bytes = value
        .devices
        .iter()
        .filter_map(|device| device.memory_bytes)
        .max();

    if value.devices.is_empty() {
        return "0 devices".to_string();
    }

    let mut parts = vec![
        format!("{} devices", value.devices.len()),
        format!("kinds {}", join_or_placeholder(&kinds)),
        format!("vendors {}", join_or_placeholder(&vendors)),
    ];
    if !families.is_empty() {
        parts.push(format!("families {}", join_or_placeholder(&families)));
    }
    if !models.is_empty() {
        parts.push(format!("models {}", join_or_placeholder(&models)));
    }
    if integrated_devices > 0 {
        parts.push(format!("{integrated_devices} integrated"));
    }
    if let Some(memory_bytes) = max_memory_bytes {
        parts.push(format!("max memory {}", format_bytes_compact(memory_bytes)));
    }
    if let Some(locality) = format_accelerator_locality_for_inspect(
        u32::try_from(value.devices.len()).ok(),
        accelerators_with_known_numa_node,
        &accelerator_numa_nodes,
    ) {
        parts.push(locality);
    }
    if !drivers.is_empty() {
        parts.push(format!("drivers {}", join_or_placeholder(&drivers)));
    }
    if let Some(operability) = value.operability.as_ref() {
        parts.push(format_accelerator_operability_for_inspect(
            operability,
            options.verbose,
        ));
    }
    if options.verbose {
        let identities = value
            .devices
            .iter()
            .map(|device| {
                let mut detail_parts = vec![device.kind.as_str().to_string()];
                detail_parts.push(format!("source {}", device.discovery_source.as_str()));
                if let Some(vendor) = device.vendor.as_ref() {
                    detail_parts.push(vendor.clone());
                }
                if let Some(family) = device.family.as_ref() {
                    detail_parts.push(format!("family {family}"));
                }
                if let Some(model) = device.model.as_ref() {
                    detail_parts.push(format!("model {model}"));
                }
                if let (Some(vendor_id), Some(device_id)) =
                    (device.vendor_id.as_ref(), device.device_id.as_ref())
                {
                    detail_parts.push(format!("{vendor_id}:{device_id}"));
                }
                if let Some(integration) = device.integration {
                    detail_parts.push(format!("integration {}", integration.as_str()));
                }
                if let Some(memory_bytes) = device.memory_bytes {
                    detail_parts.push(format!("memory {}", format_bytes_compact(memory_bytes)));
                }
                if let Some(driver) = device.driver.as_ref() {
                    detail_parts.push(format!("driver {driver}"));
                }
                if let Some(pci_address) = device.pci_address.as_ref() {
                    detail_parts.push(format!("pci {pci_address}"));
                }
                if let Some(numa_node) = device.numa_node {
                    detail_parts.push(format!("numa {numa_node}"));
                }
                detail_parts.join(" ")
            })
            .collect::<Vec<_>>();
        parts.push(format!("inventory {}", identities.join(" | ")));
    }

    parts.join("; ")
}

pub(super) fn format_accelerator_locality_for_inspect(
    total_accelerators: Option<u32>,
    accelerators_with_known_numa_node: Option<u32>,
    accelerator_numa_nodes: &[u32],
) -> Option<String> {
    let total_accelerators = total_accelerators?;
    if total_accelerators == 0 {
        return None;
    }

    match accelerators_with_known_numa_node {
        Some(known) if !accelerator_numa_nodes.is_empty() => Some(format!(
            "locality {known}/{total_accelerators} known; NUMA nodes {}",
            accelerator_numa_nodes
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )),
        Some(known) => Some(format!("locality {known}/{total_accelerators} known")),
        None => Some("locality unknown".to_string()),
    }
}

pub(super) fn format_accelerator_operability_for_inspect(
    operability: &AcceleratorOperabilityV1,
    verbose: bool,
) -> String {
    let mut parts = vec![
        format!(
            "static operability: {}",
            operability.static_operability.as_str()
        ),
        format!("{} driver-bound", operability.driver_bound_devices),
    ];
    if verbose {
        parts.push(format!(
            "nodes {}",
            if operability.visible_device_nodes.is_empty() {
                "<none>".to_string()
            } else {
                operability.visible_device_nodes.join(", ")
            }
        ));
        parts.push(format!(
            "render nodes {}",
            if operability.visible_render_nodes.is_empty() {
                "<none>".to_string()
            } else {
                operability.visible_render_nodes.join(", ")
            }
        ));
    } else if !operability.visible_device_nodes.is_empty()
        || !matches!(
            operability.static_operability,
            StaticOperabilityV1::Operable
        )
    {
        parts.push(format!(
            "{} visible nodes",
            operability.visible_device_nodes.len()
        ));
        if !operability.visible_render_nodes.is_empty()
            || !matches!(
                operability.static_operability,
                StaticOperabilityV1::Operable
            )
        {
            parts.push(format!(
                "{} render nodes",
                operability.visible_render_nodes.len()
            ));
        }
    }
    parts.join("; ")
}

pub(super) fn format_observation_state(state: &ObservationStateV1) -> &'static str {
    match state {
        ObservationStateV1::Observed => "observed",
        ObservationStateV1::Missing => "missing",
        ObservationStateV1::Unknown => "unknown",
        ObservationStateV1::PartiallyObserved => "partially_observed",
        ObservationStateV1::HiddenByPrivilegeOrVisibility => "hidden_by_privilege_or_visibility",
        ObservationStateV1::NotApplicable => "not_applicable",
    }
}

pub(super) fn format_observation_surface(
    state: &ObservationStateV1,
    limitation_reason: Option<&ObservationLimitationReasonV1>,
) -> String {
    match limitation_reason {
        Some(reason) => format!("{} ({})", format_observation_state(state), reason.as_str()),
        None => format_observation_state(state).to_string(),
    }
}

pub(super) fn format_visibility_scope(scope: &VisibilityScopeV1) -> &'static str {
    match scope {
        VisibilityScopeV1::BareMetalLike => "bare_metal_like",
        VisibilityScopeV1::VmLike => "vm_like",
        VisibilityScopeV1::ContainerRestricted => "container_restricted",
        VisibilityScopeV1::Unknown => "unknown",
    }
}

pub(super) fn format_privilege_level(level: &PrivilegeLevelV1) -> &'static str {
    match level {
        PrivilegeLevelV1::Full => "elevated",
        PrivilegeLevelV1::Limited => "limited",
    }
}

pub(super) fn format_identifier_value_for_inspect(
    value: &str,
    options: InspectRenderOptionsV1,
) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return "<none>".to_string();
    }

    if options.verbose || options.show_identifiers {
        return trimmed.to_string();
    }

    shorten_identifier_for_inspect(trimmed)
}

pub(super) fn shorten_identifier_for_inspect(value: &str) -> String {
    const EDGE_CHARS: usize = 8;

    let chars = value.chars().collect::<Vec<_>>();
    if chars.len() <= EDGE_CHARS * 2 + 3 {
        return value.to_string();
    }

    let prefix = chars[..EDGE_CHARS].iter().collect::<String>();
    let suffix = chars[chars.len() - EDGE_CHARS..].iter().collect::<String>();
    format!("{prefix}...{suffix}")
}

pub(super) fn format_validation_mode(mode: ValidationModeV1) -> &'static str {
    mode.as_str()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InspectColorRoleV1 {
    Success,
    Warning,
    Failure,
    Plain,
}

fn style_text_for_inspect(
    value: &str,
    role: InspectColorRoleV1,
    options: InspectRenderOptionsV1,
) -> String {
    if !options.style.color_enabled {
        return value.to_string();
    }

    let color_code = match (options.style.palette, role) {
        (_, InspectColorRoleV1::Plain) => None,
        (InspectPaletteV1::Default, InspectColorRoleV1::Success) => Some("32"),
        (InspectPaletteV1::Default, InspectColorRoleV1::Warning) => Some("33"),
        (InspectPaletteV1::Default, InspectColorRoleV1::Failure) => Some("31"),
    };

    match color_code {
        Some(color_code) => format!("\u{1b}[{color_code}m{value}\u{1b}[0m"),
        None => value.to_string(),
    }
}

pub(super) fn format_validation_verdict(
    verdict: ValidationVerdictV1,
    options: InspectRenderOptionsV1,
) -> String {
    let value = verdict.as_str();
    let role = match verdict {
        ValidationVerdictV1::Fit => InspectColorRoleV1::Success,
        ValidationVerdictV1::FitWithDegradation => InspectColorRoleV1::Warning,
        ValidationVerdictV1::Unfit => InspectColorRoleV1::Failure,
        ValidationVerdictV1::Indeterminate => InspectColorRoleV1::Plain,
    };
    style_text_for_inspect(value, role, options)
}

pub(super) fn format_validation_reason_code(reason_code: ValidationReasonCodeV1) -> &'static str {
    reason_code.as_str()
}

pub(super) fn format_operator_posture(verdict: ValidationVerdictV1) -> &'static str {
    match verdict {
        ValidationVerdictV1::Fit => "proceed",
        ValidationVerdictV1::FitWithDegradation => "proceed_with_degradation",
        ValidationVerdictV1::Unfit => "stop",
        ValidationVerdictV1::Indeterminate => "hold_for_evidence",
    }
}

pub(super) fn format_validation_state_freshness(
    basis: &ValidationBasisV1,
    validated_at: &str,
    options: InspectRenderOptionsV1,
) -> Option<String> {
    let observed_at = basis.state_observed_at.as_ref()?;
    let freshness_state = basis.state_freshness_state?;
    let observed_at_seconds = parse_timestamp_seconds(observed_at);
    let validated_at_seconds = parse_timestamp_seconds(validated_at);
    let age_seconds = match (observed_at_seconds, validated_at_seconds) {
        (Some(observed), Some(validated)) => Some(validated.saturating_sub(observed)),
        _ => None,
    };
    let exceeds_max_age = match (age_seconds, basis.max_state_age_seconds) {
        (Some(age), Some(max_age)) => age > max_age,
        _ => false,
    };
    let stale_at_validation = freshness_state == FreshnessStateV1::Stale || exceeds_max_age;

    let mut parts = vec![if stale_at_validation {
        "stale at validation".to_string()
    } else {
        "fresh at validation".to_string()
    }];
    parts.push(format!(
        "observed {}",
        format_timestamp_for_inspect(observed_at, options)
    ));

    if let Some(age_seconds) = age_seconds {
        parts.push(format!("age {}", format_duration_compact(age_seconds)));
    }
    if let Some(max_state_age_seconds) = basis.max_state_age_seconds {
        let max_age = format_duration_compact(max_state_age_seconds);
        if exceeds_max_age {
            parts.push(format!("max age {max_age} exceeded"));
        } else {
            parts.push(format!("max age {max_age}"));
        }
    }
    if freshness_state == FreshnessStateV1::Stale {
        parts.push("state artifact marked stale".to_string());
    }

    Some(parts.join("; "))
}

pub(super) fn format_validation_requirement_label(
    report: &ValidationReportPayloadV1,
) -> &'static str {
    if report.verdict == ValidationVerdictV1::Indeterminate
        && !report.failed_requirements.is_empty()
        && matches!(
            report.primary_reason_code,
            ValidationReasonCodeV1::StateMissing
                | ValidationReasonCodeV1::StateStale
                | ValidationReasonCodeV1::ValidationBlocked
        )
    {
        "Blocked requirements"
    } else {
        "Failed requirements"
    }
}

pub(super) fn format_recommendation_confidence(
    confidence: RecommendationConfidenceV1,
) -> &'static str {
    confidence.as_str()
}

pub(super) fn format_recommendation_freshness_state(
    freshness_state: RecommendationFreshnessStateV1,
) -> &'static str {
    freshness_state.as_str()
}

pub(super) fn format_batch_operator_posture_counts(rows: &[BatchClassificationRowV1]) -> String {
    let mut proceed = 0usize;
    let mut proceed_with_degradation = 0usize;
    let mut stop = 0usize;
    let mut hold_for_evidence = 0usize;

    for row in rows {
        match row.verdict {
            ValidationVerdictV1::Fit => proceed += 1,
            ValidationVerdictV1::FitWithDegradation => proceed_with_degradation += 1,
            ValidationVerdictV1::Unfit => stop += 1,
            ValidationVerdictV1::Indeterminate => hold_for_evidence += 1,
        }
    }

    [
        format!("proceed {proceed}"),
        format!("proceed_with_degradation {proceed_with_degradation}"),
        format!("stop {stop}"),
        format!("hold_for_evidence {hold_for_evidence}"),
    ]
    .join("; ")
}

pub(super) fn format_batch_primary_reason_tally(rows: &[BatchClassificationRowV1]) -> String {
    if rows.is_empty() {
        return "<none>".to_string();
    }

    let mut tallies = BTreeMap::new();
    for row in rows {
        *tallies
            .entry(row.primary_reason_code.as_str())
            .or_insert(0usize) += 1;
    }

    tallies
        .into_iter()
        .map(|(reason, count)| format!("{reason}={count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn format_batch_row_summaries(
    rows: &[BatchClassificationRowV1],
    max_rows: usize,
) -> String {
    if rows.is_empty() {
        return "<none>".to_string();
    }

    let limit = rows.len().min(max_rows);
    let mut summaries = rows
        .iter()
        .take(limit)
        .map(|row| {
            let mut summary = format!(
                "{} -> {}: {}",
                row.contract_artifact_id,
                row.service_profile_artifact_id,
                row.verdict.as_str()
            );
            if let Some(tier) = row.selected_degradation_tier.as_ref() {
                summary.push_str(&format!(" via {tier}"));
            }
            summary.push_str(&format!(" ({})", row.primary_reason_code.as_str()));
            summary
        })
        .collect::<Vec<_>>();

    let remaining = rows.len().saturating_sub(limit);
    if remaining > 0 {
        summaries.push(format!("... +{remaining} more"));
    }

    summaries.join(" | ")
}

pub(super) fn format_batch_verdict_matrix(
    artifact: &BatchClassificationReportV1,
    options: InspectRenderOptionsV1,
) -> Result<String, InspectError> {
    let mut rows_by_pair = BTreeMap::new();
    for row in &artifact.report.rows {
        let key = (
            row.contract_artifact_id.clone(),
            row.service_profile_artifact_id.clone(),
        );
        if rows_by_pair.insert(key.clone(), row).is_some() {
            return Err(InspectError::new(
                InspectErrorCode::InspectInputInvalid,
                "inspect_matrix_render",
                format!(
                    "batch classification report contains duplicate matrix row {}::{}",
                    key.0, key.1
                ),
            ));
        }
    }

    let contract_parts =
        batch_contract_display_parts(&artifact.classification_basis.ordered_contracts, options);
    let profile_labels = batch_profile_display_labels(
        &artifact.classification_basis.ordered_service_profiles,
        options,
    );

    let host_label_width = artifact
        .classification_basis
        .ordered_contracts
        .iter()
        .map(|contract| {
            contract_parts
                .get(contract.artifact_id.as_str())
                .map(|parts| parts.host_label.len())
                .unwrap_or(contract.artifact_id.len())
        })
        .fold("Host".len(), usize::max);
    let contract_label_width = artifact
        .classification_basis
        .ordered_contracts
        .iter()
        .map(|contract| {
            contract_parts
                .get(contract.artifact_id.as_str())
                .map(|parts| parts.contract_label.len())
                .unwrap_or(contract.artifact_id.len())
        })
        .fold("Contract".len(), usize::max);
    let profile_label_width = artifact
        .classification_basis
        .ordered_service_profiles
        .iter()
        .map(|profile| {
            profile_labels
                .get(profile.artifact_id.as_str())
                .map(String::len)
                .unwrap_or(profile.artifact_id.len())
        })
        .fold("Profile".len(), usize::max);
    let verdict_label_width = artifact
        .classification_basis
        .ordered_service_profiles
        .iter()
        .flat_map(|profile| {
            artifact
                .classification_basis
                .ordered_contracts
                .iter()
                .map(move |contract| (contract, profile))
        })
        .try_fold("Verdict".len(), |width, (contract, profile)| {
            let Some(row) =
                rows_by_pair.get(&(contract.artifact_id.clone(), profile.artifact_id.clone()))
            else {
                return Err(InspectError::new(
                    InspectErrorCode::InspectInputInvalid,
                    "inspect_matrix_render",
                    format!(
                        "batch classification report is missing matrix row {}::{}",
                        contract.artifact_id, profile.artifact_id
                    ),
                ));
            };
            Ok::<usize, InspectError>(width.max(row.verdict.as_str().len()))
        })?;

    let mut lines = Vec::new();
    lines.push("Each row checks one Profile against one Host under one Contract.".to_string());
    lines.push(
        "Profile = workload need; Host = candidate machine; Contract = host claim under policy; Verdict = fit result."
            .to_string(),
    );
    lines.push(format!(
        "{} | {} | {} | {}",
        pad_plain_cell("Profile", profile_label_width),
        pad_plain_cell("Host", host_label_width),
        pad_plain_cell("Contract", contract_label_width),
        pad_plain_cell("Verdict", verdict_label_width),
    ));
    lines.push(format!(
        "{}-+-{}-+-{}-+-{}",
        "-".repeat(profile_label_width),
        "-".repeat(host_label_width),
        "-".repeat(contract_label_width),
        "-".repeat(verdict_label_width),
    ));

    for profile in &artifact.classification_basis.ordered_service_profiles {
        for contract in &artifact.classification_basis.ordered_contracts {
            let row = rows_by_pair
                .get(&(contract.artifact_id.clone(), profile.artifact_id.clone()))
                .expect("matrix row presence already validated");
            let plain = row.verdict.as_str();
            let rendered_verdict = pad_rendered_cell(
                plain,
                format_validation_verdict(row.verdict, options),
                verdict_label_width,
            );
            let contract_label = contract_parts
                .get(contract.artifact_id.as_str())
                .map(|parts| parts.contract_label.as_str())
                .unwrap_or(contract.artifact_id.as_str());
            let host_label = contract_parts
                .get(contract.artifact_id.as_str())
                .map(|parts| parts.host_label.as_str())
                .unwrap_or(contract.artifact_id.as_str());
            let profile_label = profile_labels
                .get(profile.artifact_id.as_str())
                .map(String::as_str)
                .unwrap_or(profile.artifact_id.as_str());
            lines.push(format!(
                "{} | {} | {} | {}",
                pad_plain_cell(profile_label, profile_label_width),
                pad_plain_cell(host_label, host_label_width),
                pad_plain_cell(contract_label, contract_label_width),
                rendered_verdict
            ));
        }
    }

    Ok(lines.join("\n"))
}

pub(super) fn format_degradation_ladder(ladder: &[DegradationTierV1]) -> String {
    if ladder.is_empty() {
        return "<none>".to_string();
    }

    ladder
        .iter()
        .map(|tier| format!("{} -> {}", tier.tier_id, tier.acceptable_capability_class))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn format_assurance_predicates(predicates: &[AssurancePredicateV1]) -> String {
    if predicates.is_empty() {
        return "<none>".to_string();
    }

    predicates
        .iter()
        .map(|predicate| match predicate {
            AssurancePredicateV1::LocallyVerifiedRequired => "locally_verified_required",
            AssurancePredicateV1::HardwareAttestedRequired => "hardware_attested_required",
        })
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn format_explicit_assurance_requirements(
    requirements: &[crate::artifacts::service_profile_v1::ExplicitAssuranceRequirementV1],
) -> String {
    if requirements.is_empty() {
        return "<none>".to_string();
    }

    requirements
        .iter()
        .map(|requirement| {
            format!(
                "{} -> [{}] / [{}]",
                requirement.target,
                requirement
                    .accepted_assurance_sources
                    .iter()
                    .map(|value| value.as_str())
                    .collect::<Vec<_>>()
                    .join("|"),
                requirement
                    .accepted_derivation_stages
                    .iter()
                    .map(|value| value.as_str())
                    .collect::<Vec<_>>()
                    .join("|")
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn format_capability_classes(payload: &HostContractPayloadV1) -> String {
    if payload.core_contract.capability_classes.is_empty() {
        return "<none>".to_string();
    }

    payload
        .core_contract
        .capability_classes
        .iter()
        .map(|(class_id, claim)| {
            let status = if claim.admissible {
                "admissible"
            } else {
                "inadmissible"
            };
            format!("{class_id}={status}")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn format_collectors(collectors: &[CollectorMetadataV1]) -> String {
    if collectors.is_empty() {
        return "<none>".to_string();
    }

    collectors
        .iter()
        .map(|collector| {
            format!(
                "{}@{} [{}]",
                collector.collector_id, collector.collector_version, collector.source_family
            )
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn format_redaction_state(
    envelope: &ArtifactEnvelopeV1,
    options: InspectRenderOptionsV1,
) -> String {
    envelope
        .redaction
        .as_ref()
        .map(|redaction| {
            format!(
                "{} at {}",
                redaction.profile_id,
                format_timestamp_for_inspect(&redaction.redacted_at, options)
            )
        })
        .unwrap_or_else(|| "none".to_string())
}

pub(super) fn format_signature_state(signatures: &[SignatureEnvelopeV1]) -> String {
    if signatures.is_empty() {
        "unsigned".to_string()
    } else {
        format!("{} signature(s)", signatures.len())
    }
}

pub(super) fn format_signature_key_ids(signatures: &[SignatureEnvelopeV1]) -> String {
    if signatures.is_empty() {
        return "<none>".to_string();
    }

    signatures
        .iter()
        .map(|signature| signature.key_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn format_signature_namespaces(signatures: &[SignatureEnvelopeV1]) -> String {
    let namespaces = signatures
        .iter()
        .filter_map(|signature| signature.signature_namespace.clone())
        .filter(|namespace| !namespace.trim().is_empty())
        .collect::<BTreeSet<_>>();
    if namespaces.is_empty() {
        return "<none>".to_string();
    }

    namespaces.into_iter().collect::<Vec<_>>().join(", ")
}

pub(super) fn format_optional_str(value: Option<&str>) -> String {
    value
        .filter(|value| !value.trim().is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| "<none>".to_string())
}

pub(super) fn join_or_placeholder(values: &[String]) -> String {
    if values.is_empty() {
        "<none>".to_string()
    } else {
        values.join(", ")
    }
}

pub(super) fn format_bytes(bytes: u64) -> String {
    let gib = bytes as f64 / 1024_f64.powi(3);
    format!("{bytes} bytes ({gib:.2} GiB)")
}

pub(super) fn format_storage_details_for_inspect(
    value: &crate::survey::StorageDetailsV1,
) -> String {
    let device_summary = format_named_count_for_inspect(
        value.block_devices.len(),
        "block device",
        "block devices",
        &value.block_devices,
    );
    let mount_summary =
        format_named_count_for_inspect(value.mounts.len(), "mount", "mounts", &value.mounts);
    let mut parts = vec![device_summary];
    if !value.block_device_details.is_empty() {
        let mut class_tallies = BTreeMap::new();
        for detail in &value.block_device_details {
            *class_tallies
                .entry(detail.class.as_str().to_string())
                .or_insert(0usize) += 1;
        }
        parts.push(format!(
            "classes {}",
            format_tally_map_for_inspect(&class_tallies, 4)
        ));
    }
    parts.push(mount_summary);
    if !value.mount_details.is_empty() {
        let mut filesystem_tallies = BTreeMap::new();
        for detail in &value.mount_details {
            *filesystem_tallies
                .entry(detail.filesystem_type.clone())
                .or_insert(0usize) += 1;
        }
        parts.push(format!(
            "filesystems {}",
            format_tally_map_for_inspect(&filesystem_tallies, 4)
        ));
    }
    parts.join("; ")
}

pub(super) fn format_network_details_for_inspect(value: &NetworkDetailsV1) -> String {
    let interface_count = value.interfaces.len();
    let address_count = value
        .interface_details
        .iter()
        .map(|detail| detail.addresses.len())
        .sum::<usize>();
    let max_speed_mbps = value
        .interface_details
        .iter()
        .filter(|detail| detail.interface_virtuality == NetworkInterfaceVirtualityV1::Physical)
        .filter_map(|detail| detail.speed_mbps)
        .max();
    let known_physical_carrier_interfaces = value
        .interface_details
        .iter()
        .filter(|detail| detail.interface_virtuality == NetworkInterfaceVirtualityV1::Physical)
        .filter(|detail| detail.carrier_state != NetworkCarrierStateV1::Unknown)
        .count();
    let carrier_up_physical_interfaces = value
        .interface_details
        .iter()
        .filter(|detail| detail.interface_virtuality == NetworkInterfaceVirtualityV1::Physical)
        .filter(|detail| detail.carrier_state == NetworkCarrierStateV1::Up)
        .count();

    if value.interface_details.is_empty() {
        return match max_speed_mbps {
            Some(speed) => {
                format!("{interface_count} interfaces; {address_count} addresses; max {speed} Mbps")
            }
            None => format!("{interface_count} interfaces; {address_count} addresses"),
        };
    }

    let mut kind_counts = BTreeSet::new();
    let mut kind_tallies = BTreeMap::new();
    let mut virtuality_tallies = BTreeMap::new();
    for detail in &value.interface_details {
        *kind_tallies
            .entry(detail.interface_kind.as_str())
            .or_insert(0usize) += 1;
        *virtuality_tallies
            .entry(detail.interface_virtuality.as_str())
            .or_insert(0usize) += 1;
    }
    for (kind, count) in kind_tallies {
        kind_counts.insert(format!("{kind}={count}"));
    }

    let virtuality_summary = ["physical", "virtual", "indeterminate"]
        .iter()
        .filter_map(|key| {
            virtuality_tallies
                .get(key)
                .copied()
                .filter(|count| *count > 0)
                .map(|count| format!("{key} {count}"))
        })
        .collect::<Vec<_>>()
        .join(", ");

    let mut parts = vec![
        format!("{interface_count} interfaces"),
        format!("virtuality {virtuality_summary}"),
        format!(
            "kinds {}",
            kind_counts.into_iter().collect::<Vec<_>>().join(", ")
        ),
        format!("{address_count} addresses"),
    ];
    if let Some(summary) = value.addressability_summary.as_ref() {
        if let Some(families) = summary.non_loopback_address_families.as_deref() {
            parts.push(format!(
                "families {}",
                format_ip_address_families_for_inspect(families)
            ));
        }
        if let Some(families) = summary.default_route_families.as_deref() {
            parts.push(format!(
                "default routes {}",
                format_ip_address_families_for_inspect(families)
            ));
        }
    }
    if known_physical_carrier_interfaces > 0 {
        parts.push(format!(
            "carrier-up physical {carrier_up_physical_interfaces}/{known_physical_carrier_interfaces}"
        ));
    }
    if let Some(speed) = max_speed_mbps {
        parts.push(format!("max {speed} Mbps"));
    }

    parts.join("; ")
}

pub(super) fn format_ip_address_families_for_inspect(families: &[IpAddressFamilyV1]) -> String {
    if families.is_empty() {
        return "none".to_string();
    }

    families
        .iter()
        .map(|family| family.as_str().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn format_named_count_for_inspect(
    count: usize,
    singular_label: &str,
    plural_label: &str,
    values: &[String],
) -> String {
    match count {
        0 => format!("0 {plural_label}"),
        1 => format!("1 {singular_label} ({})", values[0]),
        2 => format!("2 {plural_label} ({}, {})", values[0], values[1]),
        _ => format!("{count} {plural_label}"),
    }
}

pub(super) fn format_tally_map_for_inspect(
    tallies: &BTreeMap<String, usize>,
    limit: usize,
) -> String {
    if tallies.is_empty() {
        return "<none>".to_string();
    }

    let mut rendered = tallies
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>();
    if rendered.len() <= limit {
        return rendered.join(", ");
    }

    let remaining = rendered.len() - limit;
    rendered.truncate(limit);
    format!("{} (+{remaining} more)", rendered.join(", "))
}

pub(super) fn format_bytes_compact(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * 1024 * 1024;

    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

pub(super) fn format_duration_compact(total_seconds: u64) -> String {
    if total_seconds == 0 {
        return "0s".to_string();
    }

    let days = total_seconds / 86_400;
    let hours = (total_seconds % 86_400) / 3_600;
    let minutes = (total_seconds % 3_600) / 60;
    let seconds = total_seconds % 60;
    let mut parts = Vec::new();

    if days > 0 {
        parts.push(format!("{days}d"));
    }
    if hours > 0 {
        parts.push(format!("{hours}h"));
    }
    if minutes > 0 {
        parts.push(format!("{minutes}m"));
    }
    if seconds > 0 {
        parts.push(format!("{seconds}s"));
    }

    parts.join(" ")
}

pub(super) fn format_timestamp_for_inspect(value: &str, options: InspectRenderOptionsV1) -> String {
    let Some(seconds) = parse_timestamp_seconds(value) else {
        return value.to_string();
    };

    let Some(formatted) = format_unix_seconds_utc(seconds) else {
        return value.to_string();
    };

    if options.verbose && formatted != value {
        format!("{formatted} ({value})")
    } else {
        formatted
    }
}

pub(super) fn parse_timestamp_seconds(value: &str) -> Option<u64> {
    if let Some(rest) = value
        .strip_prefix("epoch:")
        .or_else(|| value.strip_prefix("unix:"))
    {
        return rest.parse::<u64>().ok();
    }
    parse_rfc3339_utc_seconds(value)
}

pub(super) fn parse_rfc3339_utc_seconds(value: &str) -> Option<u64> {
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

pub(super) fn days_from_civil(year: i32, month: u32, day: u32) -> Option<u64> {
    if !(1..=12).contains(&month) || day == 0 || day > 31 {
        return None;
    }

    let adjusted_year = year - if month <= 2 { 1 } else { 0 };
    let era = if adjusted_year >= 0 {
        adjusted_year / 400
    } else {
        (adjusted_year - 399) / 400
    };
    let year_of_era = adjusted_year - era * 400;
    let shifted_month = month as i32 + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day as i32 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;

    u64::try_from(days).ok()
}

pub(super) fn format_unix_seconds_utc(seconds: u64) -> Option<String> {
    let days = i64::try_from(seconds / 86_400).ok()?;
    let seconds_of_day = seconds % 86_400;
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    let (year, month, day) = civil_from_days(days)?;

    Some(format!(
        "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC"
    ))
}

pub(super) fn civil_from_days(days: i64) -> Option<(i32, u32, u32)> {
    let z = days.checked_add(719_468)?;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }

    Some((
        i32::try_from(year).ok()?,
        u32::try_from(month).ok()?,
        u32::try_from(day).ok()?,
    ))
}

fn pad_plain_cell(value: &str, width: usize) -> String {
    format!("{value:<width$}")
}

fn pad_rendered_cell(plain: &str, rendered: String, width: usize) -> String {
    let padding = width.saturating_sub(plain.len());
    if padding == 0 {
        rendered
    } else {
        format!("{rendered}{}", " ".repeat(padding))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BatchContractDisplayPartsV1 {
    host_label: String,
    contract_label: String,
}

fn batch_contract_display_parts(
    contracts: &[BatchClassificationContractRefV1],
    options: InspectRenderOptionsV1,
) -> BTreeMap<&str, BatchContractDisplayPartsV1> {
    let artifact_ids = contracts
        .iter()
        .map(|contract| contract.artifact_id.as_str())
        .collect::<Vec<_>>();
    let fallback = fallback_batch_contract_display_parts(&artifact_ids, options);
    let mut display_parts = contracts
        .iter()
        .map(|contract| {
            let fallback_parts = fallback
                .get(contract.artifact_id.as_str())
                .cloned()
                .unwrap_or_else(|| BatchContractDisplayPartsV1 {
                    host_label: contract.artifact_id.clone(),
                    contract_label: contract.artifact_id.clone(),
                });
            let host_label = contract
                .host_alias
                .clone()
                .unwrap_or(fallback_parts.host_label);
            let contract_label = if options.show_identifiers {
                contract.artifact_id.clone()
            } else {
                contract
                    .short_display_name
                    .clone()
                    .or_else(|| contract.display_name.clone())
                    .unwrap_or(fallback_parts.contract_label)
            };
            (
                contract.artifact_id.as_str(),
                BatchContractDisplayPartsV1 {
                    host_label,
                    contract_label,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

    if !options.show_identifiers
        && display_parts
            .values()
            .all(|parts| parts.host_label.starts_with("demo-"))
    {
        for parts in display_parts.values_mut() {
            parts.host_label = parts
                .host_label
                .strip_prefix("demo-")
                .unwrap_or(parts.host_label.as_str())
                .to_string();
        }
    }

    display_parts
}

fn fallback_batch_contract_display_parts<'a>(
    artifact_ids: &[&'a str],
    options: InspectRenderOptionsV1,
) -> BTreeMap<&'a str, BatchContractDisplayPartsV1> {
    let base_labels = artifact_ids
        .iter()
        .map(|artifact_id| strip_known_prefix(artifact_id, "contract-").to_string())
        .collect::<Vec<_>>();
    let prefix_candidates = repeated_prefix_candidates(&base_labels);
    let suffix_candidates = repeated_suffix_candidates(&base_labels);
    let prefix_contract_labels = contract_labels_from_prefixes(&base_labels, &prefix_candidates);
    let suffix_contract_labels = contract_labels_from_suffixes(&base_labels, &suffix_candidates);
    let suffix_host_labels =
        host_labels_from_contract_labels(&base_labels, &suffix_contract_labels);
    let prefer_prefix_strategy = has_strong_common_prefix(&suffix_host_labels)
        && labels_are_nonempty_and_unique(&prefix_contract_labels);

    if options.show_identifiers {
        return artifact_ids
            .iter()
            .zip(base_labels.iter())
            .zip(if prefer_prefix_strategy {
                prefix_contract_labels.iter()
            } else {
                suffix_contract_labels.iter()
            })
            .map(|((artifact_id, base_label), contract_label)| {
                let display_parts =
                    normalized_batch_contract_display_parts(base_label, contract_label);
                (
                    *artifact_id,
                    BatchContractDisplayPartsV1 {
                        host_label: display_parts.host_label,
                        contract_label: (*artifact_id).to_string(),
                    },
                )
            })
            .collect();
    }

    artifact_ids
        .iter()
        .zip(base_labels.iter())
        .zip(if prefer_prefix_strategy {
            prefix_contract_labels.iter()
        } else {
            suffix_contract_labels.iter()
        })
        .map(|((artifact_id, base_label), contract_label)| {
            (
                *artifact_id,
                normalized_batch_contract_display_parts(base_label, contract_label),
            )
        })
        .collect()
}

fn batch_profile_display_labels(
    profiles: &[BatchClassificationServiceProfileRefV1],
    options: InspectRenderOptionsV1,
) -> BTreeMap<&str, String> {
    let labels = if options.show_identifiers {
        profiles
            .iter()
            .map(|profile| profile.artifact_id.clone())
            .collect::<Vec<_>>()
    } else {
        profiles
            .iter()
            .map(compact_batch_profile_label)
            .collect::<Vec<_>>()
    };

    profiles
        .iter()
        .zip(labels)
        .map(|(profile, label)| (profile.artifact_id.as_str(), label))
        .collect()
}

fn compact_batch_profile_label(profile: &BatchClassificationServiceProfileRefV1) -> String {
    if let Some(label) = profile.short_display_name.as_deref() {
        return label.to_string();
    }
    if let Some(label) = profile.display_name.as_deref() {
        return label.to_string();
    }
    let label = strip_known_prefix(profile.artifact_id.as_str(), "service-profile-");
    label
        .strip_suffix("-contract-only-v1")
        .or_else(|| label.strip_suffix("-v1"))
        .unwrap_or(label)
        .to_string()
}

fn strip_known_prefix<'a>(value: &'a str, prefix: &str) -> &'a str {
    value.strip_prefix(prefix).unwrap_or(value)
}

fn repeated_prefix_candidates(values: &[String]) -> Vec<String> {
    let mut candidates = BTreeMap::<String, std::collections::BTreeSet<String>>::new();
    for value in values {
        for prefix in hyphen_prefixes(value) {
            if let Some(remainder) = value.strip_prefix(&format!("{prefix}-")) {
                candidates
                    .entry(prefix.to_string())
                    .or_default()
                    .insert(remainder.to_string());
            }
        }
    }

    candidates
        .into_iter()
        .filter_map(|(prefix, remainders)| {
            (remainders.len() >= 2 && !prefix.is_empty()).then_some(prefix)
        })
        .collect()
}

fn repeated_suffix_candidates(values: &[String]) -> Vec<String> {
    let mut candidates = BTreeMap::<String, std::collections::BTreeSet<String>>::new();
    for value in values {
        for suffix in hyphen_suffixes(value) {
            if let Some(prefix) = value.strip_suffix(&format!("-{suffix}")) {
                candidates
                    .entry(suffix.to_string())
                    .or_default()
                    .insert(prefix.to_string());
            }
        }
    }

    candidates
        .into_iter()
        .filter_map(|(suffix, prefixes)| {
            (prefixes.len() >= 2 && !suffix.is_empty()).then_some(suffix)
        })
        .collect()
}

fn contract_labels_from_prefixes(values: &[String], prefixes: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| {
            longest_matching_prefix(value, prefixes)
                .and_then(|prefix| value.strip_prefix(&format!("{prefix}-")))
                .map(str::to_string)
                .unwrap_or_else(|| value.to_string())
        })
        .collect()
}

fn contract_labels_from_suffixes(values: &[String], suffixes: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| {
            longest_matching_suffix(value, suffixes)
                .map(str::to_string)
                .unwrap_or_else(|| value.to_string())
        })
        .collect()
}

fn host_labels_from_contract_labels(values: &[String], contract_labels: &[String]) -> Vec<String> {
    values
        .iter()
        .zip(contract_labels.iter())
        .map(|(value, contract_label)| host_label_from_contract_label(value, contract_label))
        .collect()
}

fn host_label_from_contract_label(value: &str, contract_label: &str) -> String {
    value
        .strip_suffix(&format!("-{contract_label}"))
        .unwrap_or(value)
        .to_string()
}

fn normalized_batch_contract_display_parts(
    base_label: &str,
    contract_label: &str,
) -> BatchContractDisplayPartsV1 {
    let host_label = host_label_from_contract_label(base_label, contract_label);
    let mut contract_label = contract_label.to_string();
    let normalized_host_label = if !host_label_looks_complete(&host_label) {
        if let Some((trimmed_host_label, trailing_token)) = split_last_hyphen_segment(&host_label) {
            if !trimmed_host_label.is_empty() && !trailing_token.is_empty() {
                contract_label = format!("{trailing_token}-{contract_label}");
                trimmed_host_label.to_string()
            } else {
                host_label
            }
        } else {
            host_label
        }
    } else {
        host_label
    };

    BatchContractDisplayPartsV1 {
        host_label: normalized_host_label,
        contract_label,
    }
}

fn host_label_looks_complete(host_label: &str) -> bool {
    host_label.rsplit('-').next().is_some_and(is_version_marker) || !host_label.contains('-')
}

fn split_last_hyphen_segment(value: &str) -> Option<(&str, &str)> {
    let split_index = value.rfind('-')?;
    let prefix = &value[..split_index];
    let suffix = &value[split_index + 1..];
    (!prefix.is_empty() && !suffix.is_empty()).then_some((prefix, suffix))
}

fn is_version_marker(value: &str) -> bool {
    value.starts_with('v')
        && value[1..]
            .chars()
            .all(|character| character.is_ascii_digit())
}

fn hyphen_prefixes(value: &str) -> Vec<&str> {
    value
        .match_indices('-')
        .map(|(index, _)| &value[..index])
        .filter(|candidate| !candidate.is_empty())
        .collect()
}

fn hyphen_suffixes(value: &str) -> Vec<&str> {
    value
        .match_indices('-')
        .map(|(index, _)| &value[index + 1..])
        .filter(|candidate| !candidate.is_empty())
        .collect()
}

fn longest_matching_prefix<'a>(value: &str, prefixes: &'a [String]) -> Option<&'a str> {
    prefixes
        .iter()
        .filter_map(|prefix| {
            value
                .strip_prefix(&format!("{prefix}-"))
                .is_some()
                .then_some(prefix.as_str())
        })
        .max_by_key(|prefix| prefix.len())
}

fn longest_matching_suffix<'a>(value: &str, suffixes: &'a [String]) -> Option<&'a str> {
    suffixes
        .iter()
        .filter_map(|suffix| {
            value
                .strip_suffix(&format!("-{suffix}"))
                .is_some()
                .then_some(suffix.as_str())
        })
        .min_by(|left, right| {
            version_marker_count(left)
                .cmp(&version_marker_count(right))
                .then_with(|| right.len().cmp(&left.len()))
        })
}

fn has_strong_common_prefix(values: &[String]) -> bool {
    let Some(common_prefix) = longest_common_prefix(values) else {
        return false;
    };
    let trimmed = common_prefix.trim_end_matches('-');
    if trimmed.is_empty() {
        return false;
    }
    let boundary_trimmed = trimmed
        .rfind('-')
        .map(|index| &trimmed[..index])
        .filter(|candidate| !candidate.is_empty())
        .unwrap_or(trimmed);
    let min_len = values.iter().map(String::len).min().unwrap_or(0);
    !boundary_trimmed.is_empty() && boundary_trimmed.len() * 2 >= min_len
}

fn longest_common_prefix(values: &[String]) -> Option<&str> {
    let first = values.first()?;
    let mut prefix_len = first.len();
    for value in values.iter().skip(1) {
        let mut byte_index = 0usize;
        for (left, right) in first.chars().zip(value.chars()) {
            if left != right {
                break;
            }
            byte_index += left.len_utf8();
        }
        prefix_len = prefix_len.min(byte_index);
        if prefix_len == 0 {
            return None;
        }
    }
    Some(&first[..prefix_len])
}

fn version_marker_count(value: &str) -> usize {
    value
        .split('-')
        .filter(|token| {
            token.len() > 1
                && token.starts_with('v')
                && token[1..]
                    .chars()
                    .all(|character| character.is_ascii_digit())
        })
        .count()
}

fn labels_are_nonempty_and_unique(values: &[String]) -> bool {
    !values.is_empty()
        && values.iter().all(|value| !value.is_empty())
        && values
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == values.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_verdict_coloring_is_opt_in() {
        assert_eq!(
            format_validation_verdict(ValidationVerdictV1::Fit, InspectRenderOptionsV1::default(),),
            "fit"
        );
        assert_eq!(
            format_validation_verdict(
                ValidationVerdictV1::Indeterminate,
                InspectRenderOptionsV1::default(),
            ),
            "indeterminate"
        );
    }

    #[test]
    fn validation_verdict_coloring_uses_green_yellow_and_red_mapping() {
        let options = InspectRenderOptionsV1 {
            style: InspectStyleOptionsV1 {
                color_enabled: true,
                palette: InspectPaletteV1::Default,
            },
            ..InspectRenderOptionsV1::default()
        };

        assert_eq!(
            format_validation_verdict(ValidationVerdictV1::Fit, options),
            "\u{1b}[32mfit\u{1b}[0m"
        );
        assert_eq!(
            format_validation_verdict(ValidationVerdictV1::FitWithDegradation, options),
            "\u{1b}[33mfit_with_degradation\u{1b}[0m"
        );
        assert_eq!(
            format_validation_verdict(ValidationVerdictV1::Unfit, options),
            "\u{1b}[31munfit\u{1b}[0m"
        );
        assert_eq!(
            format_validation_verdict(ValidationVerdictV1::Indeterminate, options),
            "indeterminate"
        );
    }

    #[test]
    fn semantic_color_roles_use_default_palette_when_enabled() {
        let options = InspectRenderOptionsV1 {
            style: InspectStyleOptionsV1 {
                color_enabled: true,
                palette: InspectPaletteV1::Default,
            },
            ..InspectRenderOptionsV1::default()
        };

        assert_eq!(
            style_text_for_inspect("fit", InspectColorRoleV1::Success, options),
            "\u{1b}[32mfit\u{1b}[0m"
        );
        assert_eq!(
            style_text_for_inspect("fit_with_degradation", InspectColorRoleV1::Warning, options),
            "\u{1b}[33mfit_with_degradation\u{1b}[0m"
        );
        assert_eq!(
            style_text_for_inspect("unfit", InspectColorRoleV1::Failure, options),
            "\u{1b}[31munfit\u{1b}[0m"
        );
        assert_eq!(
            style_text_for_inspect("indeterminate", InspectColorRoleV1::Plain, options),
            "indeterminate"
        );
    }

    #[test]
    fn operator_posture_maps_each_verdict_to_a_scan_friendly_label() {
        assert_eq!(format_operator_posture(ValidationVerdictV1::Fit), "proceed");
        assert_eq!(
            format_operator_posture(ValidationVerdictV1::FitWithDegradation),
            "proceed_with_degradation"
        );
        assert_eq!(format_operator_posture(ValidationVerdictV1::Unfit), "stop");
        assert_eq!(
            format_operator_posture(ValidationVerdictV1::Indeterminate),
            "hold_for_evidence"
        );
    }

    #[test]
    fn batch_reason_tally_and_row_summaries_stay_deterministic() {
        let rows = vec![
            BatchClassificationRowV1 {
                row_id: "row-a".to_string(),
                contract_artifact_id: "contract-a".to_string(),
                contract_semantic_hash: "hash-a".to_string(),
                service_profile_artifact_id: "profile-a".to_string(),
                service_profile_semantic_hash: "profile-hash-a".to_string(),
                verdict: ValidationVerdictV1::Fit,
                primary_reason_code: ValidationReasonCodeV1::RequirementsSatisfied,
                selected_degradation_tier: None,
                summary: "fit".to_string(),
            },
            BatchClassificationRowV1 {
                row_id: "row-b".to_string(),
                contract_artifact_id: "contract-a".to_string(),
                contract_semantic_hash: "hash-a".to_string(),
                service_profile_artifact_id: "profile-b".to_string(),
                service_profile_semantic_hash: "profile-hash-b".to_string(),
                verdict: ValidationVerdictV1::FitWithDegradation,
                primary_reason_code: ValidationReasonCodeV1::DegradationPathRequired,
                selected_degradation_tier: Some("fallback/general_compute".to_string()),
                summary: "degraded".to_string(),
            },
            BatchClassificationRowV1 {
                row_id: "row-c".to_string(),
                contract_artifact_id: "contract-b".to_string(),
                contract_semantic_hash: "hash-b".to_string(),
                service_profile_artifact_id: "profile-a".to_string(),
                service_profile_semantic_hash: "profile-hash-a".to_string(),
                verdict: ValidationVerdictV1::Unfit,
                primary_reason_code: ValidationReasonCodeV1::CapabilityUnknown,
                selected_degradation_tier: None,
                summary: "unfit".to_string(),
            },
        ];

        assert_eq!(
            format_batch_operator_posture_counts(&rows),
            "proceed 1; proceed_with_degradation 1; stop 1; hold_for_evidence 0"
        );
        assert_eq!(
            format_batch_primary_reason_tally(&rows),
            "capability_unknown=1, degradation_path_required=1, requirements_satisfied=1"
        );
        assert_eq!(
            format_batch_row_summaries(&rows, 2),
            "contract-a -> profile-a: fit (requirements_satisfied) | contract-a -> profile-b: fit_with_degradation via fallback/general_compute (degradation_path_required) | ... +1 more"
        );
    }

    #[test]
    fn batch_verdict_matrix_uses_declared_contract_and_profile_order() {
        let artifact = BatchClassificationReportV1 {
            envelope: crate::artifacts::envelope_v1::ArtifactEnvelopeV1 {
                schema_id: crate::artifacts::schema_ids_v1::BATCH_CLASSIFICATION_REPORT_SCHEMA_ID
                    .to_string(),
                schema_version: crate::artifacts::schema_ids_v1::TOP_LEVEL_ARTIFACT_SCHEMA_VERSION,
                artifact_id: "batch-demo".to_string(),
                provenance: crate::artifacts::envelope_v1::ArtifactProvenanceV1 {
                    source: "classify:contract_only".to_string(),
                    collected_at: "2025-04-21T14:37:19Z".to_string(),
                    fitctl_version: Some("0.2.0".to_string()),
                    command_name: Some("classify".to_string()),
                    correlation_id: Some("batch-demo".to_string()),
                },
                redaction: None,
                signatures: vec![],
            },
            classification_basis:
                crate::artifacts::batch_classification_report_v1::BatchClassificationBasisV1 {
                    validation_mode: ValidationModeV1::ContractOnly,
                    validated_at: "2025-04-21T14:37:19Z".to_string(),
                    validation_engine_id: "fitctl.validate.v1".to_string(),
                    validation_engine_version: "1".to_string(),
                    ordered_contracts: vec![
                        crate::artifacts::batch_classification_report_v1::BatchClassificationContractRefV1 {
                            artifact_id: "contract-b".to_string(),
                            semantic_hash: "hash-b".to_string(),
                            host_alias: None,
                            display_name: None,
                            short_display_name: None,
                        },
                        crate::artifacts::batch_classification_report_v1::BatchClassificationContractRefV1 {
                            artifact_id: "contract-a".to_string(),
                            semantic_hash: "hash-a".to_string(),
                            host_alias: None,
                            display_name: None,
                            short_display_name: None,
                        },
                    ],
                    ordered_service_profiles: vec![
                        crate::artifacts::batch_classification_report_v1::BatchClassificationServiceProfileRefV1 {
                            artifact_id: "service-profile-z".to_string(),
                            semantic_hash: "hash-z".to_string(),
                            display_name: None,
                            short_display_name: None,
                        },
                        crate::artifacts::batch_classification_report_v1::BatchClassificationServiceProfileRefV1 {
                            artifact_id: "service-profile-a".to_string(),
                            semantic_hash: "hash-a".to_string(),
                            display_name: None,
                            short_display_name: None,
                        },
                    ],
                },
            report:
                crate::artifacts::batch_classification_report_v1::BatchClassificationReportPayloadV1 {
                    rows: vec![
                        BatchClassificationRowV1 {
                            row_id: "b-z".to_string(),
                            contract_artifact_id: "contract-b".to_string(),
                            contract_semantic_hash: "hash-b".to_string(),
                            service_profile_artifact_id: "service-profile-z".to_string(),
                            service_profile_semantic_hash: "hash-z".to_string(),
                            verdict: ValidationVerdictV1::Fit,
                            primary_reason_code: ValidationReasonCodeV1::RequirementsSatisfied,
                            selected_degradation_tier: None,
                            summary: "fit".to_string(),
                        },
                        BatchClassificationRowV1 {
                            row_id: "b-a".to_string(),
                            contract_artifact_id: "contract-b".to_string(),
                            contract_semantic_hash: "hash-b".to_string(),
                            service_profile_artifact_id: "service-profile-a".to_string(),
                            service_profile_semantic_hash: "hash-a".to_string(),
                            verdict: ValidationVerdictV1::FitWithDegradation,
                            primary_reason_code: ValidationReasonCodeV1::DegradationPathRequired,
                            selected_degradation_tier: Some(
                                "fallback/general_compute".to_string(),
                            ),
                            summary: "degraded".to_string(),
                        },
                        BatchClassificationRowV1 {
                            row_id: "a-z".to_string(),
                            contract_artifact_id: "contract-a".to_string(),
                            contract_semantic_hash: "hash-a".to_string(),
                            service_profile_artifact_id: "service-profile-z".to_string(),
                            service_profile_semantic_hash: "hash-z".to_string(),
                            verdict: ValidationVerdictV1::Unfit,
                            primary_reason_code: ValidationReasonCodeV1::CapabilityUnknown,
                            selected_degradation_tier: None,
                            summary: "unfit".to_string(),
                        },
                        BatchClassificationRowV1 {
                            row_id: "a-a".to_string(),
                            contract_artifact_id: "contract-a".to_string(),
                            contract_semantic_hash: "hash-a".to_string(),
                            service_profile_artifact_id: "service-profile-a".to_string(),
                            service_profile_semantic_hash: "hash-a".to_string(),
                            verdict: ValidationVerdictV1::Indeterminate,
                            primary_reason_code: ValidationReasonCodeV1::StateStale,
                            selected_degradation_tier: None,
                            summary: "indeterminate".to_string(),
                        },
                    ],
                    contract_summaries: vec![],
                    service_profile_summaries: vec![],
                },
        };

        let matrix = format_batch_verdict_matrix(&artifact, InspectRenderOptionsV1::default())
            .expect("matrix should render");

        assert!(matrix.contains("Host"));
        assert!(matrix.contains("Contract"));
        assert!(matrix.contains("Profile"));
        assert!(matrix.contains("Verdict"));
        let lines = matrix.lines().collect::<Vec<_>>();
        let b_z_row = lines
            .iter()
            .position(|line| {
                line.contains("b")
                    && line.contains("z")
                    && line.contains("fit")
                    && !line.contains("fit_with_degradation")
            })
            .expect("b/z row should exist");
        let b_a_row = lines
            .iter()
            .position(|line| {
                line.contains("b") && line.contains("a") && line.contains("fit_with_degradation")
            })
            .expect("b/a row should exist");
        let a_z_row = lines
            .iter()
            .position(|line| {
                line.contains("a")
                    && line.contains("z")
                    && line.contains("unfit")
                    && !line.contains("fit_with_degradation")
            })
            .expect("a/z row should exist");
        assert!(b_z_row < a_z_row);
        assert!(a_z_row < b_a_row);
        assert!(lines
            .iter()
            .any(|line| { line.contains("b") && line.contains("z") && line.contains("fit") }));
        assert!(lines.iter().any(|line| {
            line.contains("b") && line.contains("a") && line.contains("fit_with_degradation")
        }));
        assert!(lines
            .iter()
            .any(|line| { line.contains("a") && line.contains("z") && line.contains("unfit") }));
        assert!(lines
            .iter()
            .any(|line| { line.contains("a") && line.contains("indeterminate") }));
        assert!(matrix.contains("fit_with_degradation"));
        assert!(matrix.contains("indeterminate"));
    }

    #[test]
    fn batch_contract_display_parts_split_same_host_multi_policy_labels() {
        let contracts = [
            BatchClassificationContractRefV1 {
                artifact_id: "contract-linux-gpu-workstation-like-v1-general-compute-default-v1"
                    .to_string(),
                semantic_hash: "hash-a".to_string(),
                host_alias: None,
                display_name: None,
                short_display_name: None,
            },
            BatchClassificationContractRefV1 {
                artifact_id: "contract-linux-gpu-workstation-like-v1-gpu-compute-default-v1"
                    .to_string(),
                semantic_hash: "hash-b".to_string(),
                host_alias: None,
                display_name: None,
                short_display_name: None,
            },
        ];
        let labels = batch_contract_display_parts(&contracts, InspectRenderOptionsV1::default());

        assert_eq!(
            labels
                .get("contract-linux-gpu-workstation-like-v1-general-compute-default-v1")
                .map(|parts| parts.host_label.as_str()),
            Some("linux-gpu-workstation-like-v1")
        );
        assert_eq!(
            labels
                .get("contract-linux-gpu-workstation-like-v1-gpu-compute-default-v1")
                .map(|parts| parts.host_label.as_str()),
            Some("linux-gpu-workstation-like-v1")
        );
        assert_eq!(
            labels
                .get("contract-linux-gpu-workstation-like-v1-general-compute-default-v1")
                .map(|parts| parts.contract_label.as_str()),
            Some("general-compute-default-v1")
        );
        assert_eq!(
            labels
                .get("contract-linux-gpu-workstation-like-v1-gpu-compute-default-v1")
                .map(|parts| parts.contract_label.as_str()),
            Some("gpu-compute-default-v1")
        );
    }

    #[test]
    fn batch_contract_display_parts_split_multi_host_single_policy_labels() {
        let contracts = [
            BatchClassificationContractRefV1 {
                artifact_id: "contract-linux-bare-metal-like-v1-general-compute-default-v1"
                    .to_string(),
                semantic_hash: "hash-a".to_string(),
                host_alias: None,
                display_name: None,
                short_display_name: None,
            },
            BatchClassificationContractRefV1 {
                artifact_id: "contract-linux-gpu-workstation-like-v1-general-compute-default-v1"
                    .to_string(),
                semantic_hash: "hash-b".to_string(),
                host_alias: None,
                display_name: None,
                short_display_name: None,
            },
        ];
        let labels = batch_contract_display_parts(&contracts, InspectRenderOptionsV1::default());

        assert_eq!(
            labels
                .get("contract-linux-bare-metal-like-v1-general-compute-default-v1")
                .map(|parts| parts.host_label.as_str()),
            Some("linux-bare-metal-like-v1")
        );
        assert_eq!(
            labels
                .get("contract-linux-gpu-workstation-like-v1-general-compute-default-v1")
                .map(|parts| parts.host_label.as_str()),
            Some("linux-gpu-workstation-like-v1")
        );
        assert_eq!(
            labels
                .get("contract-linux-bare-metal-like-v1-general-compute-default-v1")
                .map(|parts| parts.contract_label.as_str()),
            Some("general-compute-default-v1")
        );
        assert_eq!(
            labels
                .get("contract-linux-gpu-workstation-like-v1-general-compute-default-v1")
                .map(|parts| parts.contract_label.as_str()),
            Some("general-compute-default-v1")
        );
    }

    #[test]
    fn batch_contract_display_parts_split_mixed_host_and_policy_labels() {
        let contracts = [
            BatchClassificationContractRefV1 {
                artifact_id: "contract-linux-bare-metal-like-v1-general-compute-default-v1"
                    .to_string(),
                semantic_hash: "hash-a".to_string(),
                host_alias: None,
                display_name: None,
                short_display_name: None,
            },
            BatchClassificationContractRefV1 {
                artifact_id: "contract-linux-network-mixed-like-v1-general-compute-default-v1"
                    .to_string(),
                semantic_hash: "hash-b".to_string(),
                host_alias: None,
                display_name: None,
                short_display_name: None,
            },
            BatchClassificationContractRefV1 {
                artifact_id: "contract-linux-gpu-dual-numa-like-v1-gpu-compute-default-v1"
                    .to_string(),
                semantic_hash: "hash-c".to_string(),
                host_alias: None,
                display_name: None,
                short_display_name: None,
            },
        ];
        let labels = batch_contract_display_parts(&contracts, InspectRenderOptionsV1::default());

        assert_eq!(
            labels
                .get("contract-linux-bare-metal-like-v1-general-compute-default-v1")
                .map(|parts| (parts.host_label.as_str(), parts.contract_label.as_str())),
            Some(("linux-bare-metal-like-v1", "general-compute-default-v1"))
        );
        assert_eq!(
            labels
                .get("contract-linux-network-mixed-like-v1-general-compute-default-v1")
                .map(|parts| (parts.host_label.as_str(), parts.contract_label.as_str())),
            Some(("linux-network-mixed-like-v1", "general-compute-default-v1"))
        );
        assert_eq!(
            labels
                .get("contract-linux-gpu-dual-numa-like-v1-gpu-compute-default-v1")
                .map(|parts| (parts.host_label.as_str(), parts.contract_label.as_str())),
            Some(("linux-gpu-dual-numa-like-v1", "gpu-compute-default-v1"))
        );
    }

    #[test]
    fn batch_contract_display_parts_prefer_explicit_host_and_contract_labels() {
        let contracts = [BatchClassificationContractRefV1 {
            artifact_id: "contract-linux-bare-metal-like-v1-general-compute-default-v1".to_string(),
            semantic_hash: "hash-a".to_string(),
            host_alias: Some("bare-01".to_string()),
            display_name: Some("bare-01/General compute default policy".to_string()),
            short_display_name: Some("General compute default".to_string()),
        }];
        let labels = batch_contract_display_parts(&contracts, InspectRenderOptionsV1::default());

        assert_eq!(
            labels
                .get("contract-linux-bare-metal-like-v1-general-compute-default-v1")
                .map(|parts| (parts.host_label.as_str(), parts.contract_label.as_str())),
            Some(("bare-01", "General compute default"))
        );
    }

    #[test]
    fn batch_contract_display_parts_strip_shared_demo_prefix_from_host_aliases() {
        let contracts = [
            BatchClassificationContractRefV1 {
                artifact_id: "contract-linux-bare-metal-like-v1-general-compute-default-v1"
                    .to_string(),
                semantic_hash: "hash-a".to_string(),
                host_alias: Some("demo-baremetal-01".to_string()),
                display_name: Some(
                    "demo-baremetal-01 / General compute default policy".to_string(),
                ),
                short_display_name: Some("General compute default".to_string()),
            },
            BatchClassificationContractRefV1 {
                artifact_id: "contract-linux-gpu-workstation-like-v1-gpu-compute-default-v1"
                    .to_string(),
                semantic_hash: "hash-b".to_string(),
                host_alias: Some("demo-gpu-01".to_string()),
                display_name: Some("demo-gpu-01 / GPU compute default policy".to_string()),
                short_display_name: Some("GPU compute default".to_string()),
            },
        ];
        let labels = batch_contract_display_parts(&contracts, InspectRenderOptionsV1::default());

        assert_eq!(
            labels
                .get("contract-linux-bare-metal-like-v1-general-compute-default-v1")
                .map(|parts| parts.host_label.as_str()),
            Some("baremetal-01")
        );
        assert_eq!(
            labels
                .get("contract-linux-gpu-workstation-like-v1-gpu-compute-default-v1")
                .map(|parts| parts.host_label.as_str()),
            Some("gpu-01")
        );
    }

    #[test]
    fn batch_profile_display_labels_compact_contract_only_suffixes() {
        let profiles = [
            crate::artifacts::batch_classification_report_v1::BatchClassificationServiceProfileRefV1 {
                artifact_id: "service-profile-general-compute-no-gpu-contract-only-v1".to_string(),
                semantic_hash: "hash-a".to_string(),
                display_name: Some("CPU only".to_string()),
                short_display_name: Some("CPU only".to_string()),
            },
            crate::artifacts::batch_classification_report_v1::BatchClassificationServiceProfileRefV1 {
                artifact_id: "service-profile-gpu-preferred-with-general-compute-fallback-contract-only-v1".to_string(),
                semantic_hash: "hash-b".to_string(),
                display_name: Some("GPU preferred with CPU fallback".to_string()),
                short_display_name: Some("GPU preferred, CPU fallback".to_string()),
            },
            crate::artifacts::batch_classification_report_v1::BatchClassificationServiceProfileRefV1 {
                artifact_id: "service-profile-gpu-required-contract-only-v1".to_string(),
                semantic_hash: "hash-c".to_string(),
                display_name: Some("GPU required".to_string()),
                short_display_name: Some("GPU required".to_string()),
            },
        ];
        let labels = batch_profile_display_labels(&profiles, InspectRenderOptionsV1::default());

        assert_eq!(
            labels
                .get("service-profile-general-compute-no-gpu-contract-only-v1")
                .map(String::as_str),
            Some("CPU only")
        );
        assert_eq!(
            labels
                .get("service-profile-gpu-preferred-with-general-compute-fallback-contract-only-v1")
                .map(String::as_str),
            Some("GPU preferred, CPU fallback")
        );
        assert_eq!(
            labels
                .get("service-profile-gpu-required-contract-only-v1")
                .map(String::as_str),
            Some("GPU required")
        );
    }
}
