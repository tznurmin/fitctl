// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Formatting helpers shared by the inspect renderer.

use super::*;
use crate::artifacts::state_v1::FreshnessStateV1;
use crate::artifacts::validation_report_v1::{ValidationBasisV1, ValidationReportPayloadV1};
use crate::survey::IpAddressFamilyV1;

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
    let mut drivers = value
        .devices
        .iter()
        .filter_map(|device| device.driver.clone())
        .collect::<Vec<_>>();
    drivers.sort();
    drivers.dedup();

    if value.devices.is_empty() {
        return "0 devices".to_string();
    }

    let mut parts = vec![
        format!("{} devices", value.devices.len()),
        format!("kinds {}", join_or_placeholder(&kinds)),
        format!("vendors {}", join_or_placeholder(&vendors)),
    ];
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
                if let (Some(vendor_id), Some(device_id)) =
                    (device.vendor_id.as_ref(), device.device_id.as_ref())
                {
                    detail_parts.push(format!("{vendor_id}:{device_id}"));
                }
                if let Some(driver) = device.driver.as_ref() {
                    detail_parts.push(format!("driver {driver}"));
                }
                if let Some(pci_address) = device.pci_address.as_ref() {
                    detail_parts.push(format!("pci {pci_address}"));
                }
                detail_parts.join(" ")
            })
            .collect::<Vec<_>>();
        parts.push(format!("inventory {}", identities.join(" | ")));
    }

    parts.join("; ")
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
    } else if !operability.visible_device_nodes.is_empty() {
        parts.push(format!(
            "{} visible nodes",
            operability.visible_device_nodes.len()
        ));
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

pub(super) fn format_validation_verdict(verdict: ValidationVerdictV1) -> &'static str {
    verdict.as_str()
}

pub(super) fn format_validation_reason_code(reason_code: ValidationReasonCodeV1) -> &'static str {
    reason_code.as_str()
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
