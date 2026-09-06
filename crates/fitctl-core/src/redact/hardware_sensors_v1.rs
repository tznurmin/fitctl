// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Preserve sensor quantities and cross-references while removing display and host identities.

use super::profile_v1::BuiltInRedactionProfileV1;
use super::{RedactionError, RedactionErrorCode};
use crate::artifacts::hardware_sensor_resources_v1::HardwareSensorResourcesV1;
use crate::artifacts::hardware_sensor_validation_v1::validate_hardware_sensor_resources_v1;
use std::collections::BTreeMap;

pub(super) fn redact(
    s: &mut HardwareSensorResourcesV1,
    p: BuiltInRedactionProfileV1,
) -> Result<(), RedactionError> {
    // Direct Rust callers may bypass the loader. Validate links before replacing identities.
    validate_hardware_sensor_resources_v1(s).map_err(|error| {
        RedactionError::new(
            RedactionErrorCode::ArtifactInputInvalid,
            "redaction_preflight",
            error.message,
        )
    })?;
    if s.collector_host.host_alias.is_some() {
        s.collector_host.host_alias = Some(p.host_placeholder());
    }
    if s.collector_host.local_stable_id.is_some() {
        s.collector_host.local_stable_id = Some(p.local_stable_identity_placeholder());
    }
    let ids: BTreeMap<_, _> = s
        .providers
        .iter()
        .enumerate()
        .map(|(i, v)| {
            (
                v.provider_id.clone(),
                p.indexed_placeholder("hardware_provider", i),
            )
        })
        .collect();
    let chips: BTreeMap<_, _> = s
        .readings
        .iter()
        .map(|r| r.chip_id.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .enumerate()
        .map(|(i, c)| (c, p.indexed_placeholder("hardware_chip", i)))
        .collect();
    for provider in &mut s.providers {
        provider.provider_id = ids[&provider.provider_id].clone();
        if provider.evidence_target.host_id.is_some() {
            provider.evidence_target.host_id = Some(p.host_placeholder());
        }
        if provider.diagnostics.is_some() {
            provider.diagnostics = Some("redacted:hardware_sensor_diagnostic".to_owned());
        }
    }
    for (i, r) in s.readings.iter_mut().enumerate() {
        r.sensor_id = p.indexed_placeholder("hardware_sensor", i);
        r.provider_id = ids[&r.provider_id].clone();
        r.chip_id = chips[&r.chip_id].clone();
        r.raw_label = p.indexed_placeholder("hardware_label", i);
        if r.evidence_target.host_id.is_some() {
            r.evidence_target.host_id = Some(p.host_placeholder());
        }
    }
    Ok(())
}
