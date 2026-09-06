// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Structural and validity checks shared by state, inspect, redaction and signed semantic bytes.

use super::hardware_sensor_outcome_v1::provider_consistent;
use super::hardware_sensor_resources_v1::*;
use super::state_v1::{
    HostStateThermalEvidenceTargetV1, ThermalCollectionPathV1, ThermalEvidenceTargetKindV1,
};
use super::validation_v1::{ArtifactValidationError, ArtifactValidationErrorCode};
use crate::state::hardware_sensor_channels_v1 as registry;
use crate::state::hardware_sensors_v1::{
    MAX_HARDWARE_SENSOR_READINGS, MAX_HARDWARE_SENSOR_STRING_BYTES,
};
use std::collections::{BTreeMap, BTreeSet};

fn error(reason: &str) -> ArtifactValidationError {
    ArtifactValidationError {
        code: ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
        message: format!("hardware_sensor_artifact: {reason}"),
        error_model_id: "fitctl.hardware_sensor_evidence.v1",
        error_model_version: 1,
    }
}
fn text(s: &str) -> bool {
    !s.trim().is_empty() && s.len() <= MAX_HARDWARE_SENSOR_STRING_BYTES
}
fn target(t: &HostStateThermalEvidenceTargetV1) -> bool {
    match t.target_kind {
        ThermalEvidenceTargetKindV1::CurrentHost => {
            t.host_id.is_none() && t.collection_path == ThermalCollectionPathV1::LocalProcess
        }
        ThermalEvidenceTargetKindV1::HostId => t.host_id.as_deref().is_some_and(text),
    }
}
fn numeric(
    value: Option<i64>,
    state: HardwareSensorValueStateV1,
    reason: Option<HardwareSensorReasonV1>,
    q: HardwareSensorQuantityV1,
    fault: bool,
) -> bool {
    use HardwareSensorReasonV1::*;
    if value.is_some_and(|v| !registry::value_valid(q, v)) {
        return false;
    }
    match state {
        HardwareSensorValueStateV1::Observed => value.is_some() && reason.is_none() && !fault,
        HardwareSensorValueStateV1::Faulted => {
            value.is_some() && fault && reason == Some(HardwareSensorFaultAsserted)
        }
        HardwareSensorValueStateV1::Unavailable => {
            value.is_none() && reason == Some(HardwareSensorValueUnavailable)
        }
        HardwareSensorValueStateV1::Malformed => {
            value.is_none()
                && matches!(
                    reason,
                    Some(HardwareSensorValueInvalid | HardwareSensorValueOutOfRange)
                )
        }
    }
}

pub fn validate_hardware_sensor_resources_v1(
    s: &HardwareSensorResourcesV1,
) -> Result<(), ArtifactValidationError> {
    if !text(&s.observed_at)
        || s.providers.is_empty()
        || s.providers.len() > MAX_HARDWARE_SENSOR_READINGS
        || s.readings.len() > MAX_HARDWARE_SENSOR_READINGS
        || s.collector_host
            .host_alias
            .as_deref()
            .is_some_and(|v| !text(v))
        || s.collector_host
            .local_stable_id
            .as_deref()
            .is_some_and(|v| !text(v))
    {
        return Err(error("hardware_sensor_schema_invalid"));
    }
    let mut providers = BTreeMap::new();
    for p in &s.providers {
        if !text(&p.provider_id)
            || !text(&p.observed_at)
            || !target(&p.evidence_target)
            || p.observed_at != s.observed_at
            || p.diagnostics.as_deref().is_some_and(|s| !text(s))
            || providers.insert(p.provider_id.as_str(), p).is_some()
        {
            return Err(error("hardware_sensor_identity_mismatch"));
        }
    }
    let mut ids = BTreeSet::new();
    let mut channels = BTreeSet::new();
    for r in &s.readings {
        let p = providers
            .get(r.provider_id.as_str())
            .ok_or_else(|| error("hardware_sensor_identity_mismatch"))?;
        if [
            &r.sensor_id,
            &r.chip_id,
            &r.channel_id,
            &r.raw_label,
            &r.observed_at,
        ]
        .iter()
        .any(|v| !text(v))
            || !ids.insert(&r.sensor_id)
            || !channels.insert((&r.provider_id, &r.chip_id, &r.channel_id))
            || r.evidence_target != p.evidence_target
            || r.observed_at != p.observed_at
        {
            return Err(error("hardware_sensor_identity_mismatch"));
        }
        validate_reading(r)?;
    }
    for p in &s.providers {
        let rs: Vec<_> = s
            .readings
            .iter()
            .filter(|r| r.provider_id == p.provider_id)
            .collect();
        if !provider_consistent(p, &rs) {
            return Err(error(
                "hardware_sensor_schema_invalid: contradictory provider outcome",
            ));
        }
    }
    Ok(())
}

fn validate_reading(r: &HardwareSensorReadingV1) -> Result<(), ArtifactValidationError> {
    let ch = registry::channel(&r.channel_id)
        .ok_or_else(|| error("hardware_sensor_schema_invalid: channel"))?;
    if ch.quantity != r.quantity
        || ch.kind != r.measurement_kind
        || registry::unit(r.quantity) != r.unit
    {
        return Err(error("hardware_sensor_quantity_unit_mismatch"));
    }
    let fault = r.flags.iter().any(|f| {
        f.kind == HardwareSensorFlagKindV1::Fault && f.state == HardwareSensorFlagStateV1::Asserted
    });
    if !numeric(r.value, r.value_state, r.reason_code, r.quantity, fault) {
        return Err(error("hardware_sensor_schema_invalid: value state"));
    }
    let mut seen = BTreeSet::new();
    for limit in &r.limits {
        if !registry::limits(r.quantity, r.measurement_kind)
            .iter()
            .any(|(_, k)| *k == limit.kind)
            || !seen.insert(format!("{:?}", limit.kind))
            || limit.quantity != r.quantity
            || limit.unit != r.unit
            || !numeric(
                limit.value,
                limit.value_state,
                limit.reason_code,
                r.quantity,
                false,
            )
        {
            return Err(error("hardware_sensor_schema_invalid: limit"));
        }
    }
    seen.clear();
    for flag in &r.flags {
        let valid_state = match flag.state {
            HardwareSensorFlagStateV1::Asserted | HardwareSensorFlagStateV1::Clear => {
                flag.reason_code.is_none()
            }
            HardwareSensorFlagStateV1::Malformed => {
                flag.reason_code == Some(HardwareSensorReasonV1::HardwareSensorFlagInvalid)
            }
            HardwareSensorFlagStateV1::Unavailable => {
                flag.reason_code == Some(HardwareSensorReasonV1::HardwareSensorValueUnavailable)
            }
        };
        if !valid_state
            || !seen.insert(format!("{:?}", flag.kind))
            || !registry::flags(r.quantity)
                .iter()
                .any(|(_, k)| *k == flag.kind)
        {
            return Err(error("hardware_sensor_schema_invalid: flag"));
        }
    }
    Ok(())
}
