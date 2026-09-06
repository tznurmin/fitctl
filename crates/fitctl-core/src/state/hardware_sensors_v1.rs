// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Pure bounded projection of classic lm-sensors JSON into typed hardware observations.

use super::hardware_sensor_channels_v1::{self as registry, Channel};
use super::hardware_sensor_json_v1::decode;
use crate::artifacts::hardware_sensor_outcome_v1::projection_outcome;
use crate::artifacts::hardware_sensor_resources_v1::*;
use crate::artifacts::state_v1::{
    HostStateThermalCollectorHostV1, HostStateThermalEvidenceTargetV1,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const MAX_HARDWARE_SENSOR_READINGS: usize = 4096;
pub const MAX_HARDWARE_SENSOR_STRING_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensorError {
    pub error_model_id: &'static str,
    pub error_model_version: u32,
    pub reason_code: HardwareSensorReasonV1,
    pub checkpoint_id: &'static str,
}
impl SensorError {
    pub(crate) fn new(reason_code: HardwareSensorReasonV1, checkpoint_id: &'static str) -> Self {
        Self {
            error_model_id: "fitctl.hardware_sensor_evidence.v1",
            error_model_version: 1,
            reason_code,
            checkpoint_id,
        }
    }
}

pub fn parse_hardware_sensors_json_v1(
    output: &str,
    provider_id: &str,
    observed_at: &str,
    collector_host: HostStateThermalCollectorHostV1,
    evidence_target: HostStateThermalEvidenceTargetV1,
) -> Result<HardwareSensorResourcesV1, SensorError> {
    use HardwareSensorReasonV1::*;
    if output.len() > 1_048_576 {
        return Err(SensorError::new(
            HardwareSensorOutputLimit,
            "hardware_sensor_collect",
        ));
    }
    check_string(provider_id)?;
    let json = decode(output)?;
    let malformed = || SensorError::new(HardwareSensorJsonMalformed, "hardware_sensor_decode");
    let chips = json.as_object().ok_or_else(malformed)?;
    let mut readings = Vec::new();
    let mut identities = BTreeSet::new();
    for (chip, chip_value) in chips {
        check_string(chip)?;
        let features = chip_value.as_object().ok_or_else(malformed)?;
        for (label, feature) in features {
            check_string(label)?;
            if label == "Adapter" && feature.is_string() {
                continue;
            }
            let fields = feature.as_object().ok_or_else(malformed)?;
            if fields
                .iter()
                .any(|(key, value)| !key.contains('_') && value.is_object())
            {
                return Err(malformed());
            }
            let candidates = candidate_channels(fields);
            for field in candidates {
                let ch = registry::channel(&field).expect("candidate channel is registered");
                if !identities.insert((chip.clone(), field.clone())) {
                    return Err(SensorError::new(
                        HardwareSensorIdentityMismatch,
                        "hardware_sensor_normalize",
                    ));
                }
                if readings.len() == MAX_HARDWARE_SENSOR_READINGS {
                    return Err(SensorError::new(
                        HardwareSensorStructureLimit,
                        "hardware_sensor_normalize",
                    ));
                }
                readings.push(reading(
                    fields,
                    &ch,
                    ReadingContext {
                        chip,
                        label,
                        field: &field,
                        provider_id,
                        observed_at,
                        target: &evidence_target,
                    },
                )?);
            }
        }
    }
    readings.sort_by(|a, b| a.sensor_id.cmp(&b.sensor_id));
    let (outcome, reason_code) = projection_outcome(&readings.iter().collect::<Vec<_>>());
    Ok(HardwareSensorResourcesV1 {
        observed_at: observed_at.to_owned(),
        collector_host,
        providers: vec![HardwareSensorProviderV1 {
            provider_id: provider_id.to_owned(),
            provider_kind: HardwareSensorProviderKindV1::LmSensorsJson,
            outcome,
            evidence_target,
            observed_at: observed_at.to_owned(),
            reason_code,
            diagnostics: None,
        }],
        readings,
    })
}

fn candidate_channels(fields: &Map<String, Value>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for key in fields.keys() {
        if registry::channel(key).is_some() {
            out.insert(key.clone());
            continue;
        }
        let Some((base, suffix)) = key.split_once('_') else {
            continue;
        };
        for ending in ["input", "average"] {
            let field = format!("{base}_{ending}");
            let Some(ch) = registry::channel(&field) else {
                continue;
            };
            let known_limit = registry::limits(ch.quantity, ch.kind)
                .iter()
                .any(|(s, _)| *s == suffix);
            // Channel-wide flags attach to an existing average without inventing an input.
            let known_flag = ending == "input"
                && !fields.contains_key(&format!("{base}_average"))
                && registry::flags(ch.quantity)
                    .iter()
                    .any(|(s, _)| *s == suffix);
            if known_limit || known_flag {
                out.insert(field);
            }
        }
    }
    out
}

fn numeric(
    value: Option<&Value>,
    quantity: HardwareSensorQuantityV1,
) -> (
    Option<i64>,
    HardwareSensorValueStateV1,
    Option<HardwareSensorReasonV1>,
) {
    match value.map(|v| registry::scaled(v, quantity)) {
        None => (
            None,
            HardwareSensorValueStateV1::Unavailable,
            Some(HardwareSensorReasonV1::HardwareSensorValueUnavailable),
        ),
        Some(Err(reason)) => (None, HardwareSensorValueStateV1::Malformed, Some(reason)),
        Some(Ok(value)) => (Some(value), HardwareSensorValueStateV1::Observed, None),
    }
}

struct ReadingContext<'a> {
    chip: &'a str,
    label: &'a str,
    field: &'a str,
    provider_id: &'a str,
    observed_at: &'a str,
    target: &'a HostStateThermalEvidenceTargetV1,
}

fn reading(
    fields: &Map<String, Value>,
    ch: &Channel,
    context: ReadingContext<'_>,
) -> Result<HardwareSensorReadingV1, SensorError> {
    let ReadingContext {
        chip,
        label,
        field,
        provider_id,
        observed_at,
        target,
    } = context;
    check_string(field)?;
    let (value, mut value_state, mut reason_code) = numeric(fields.get(field), ch.quantity);
    let limits = registry::limits(ch.quantity, ch.kind)
        .iter()
        .filter_map(|(suffix, kind)| {
            fields.get(&format!("{}_{suffix}", ch.base)).map(|v| {
                let (value, value_state, reason_code) = numeric(Some(v), ch.quantity);
                HardwareSensorLimitV1 {
                    kind: *kind,
                    source: HardwareSensorLimitSourceV1::ProviderReported,
                    quantity: ch.quantity,
                    unit: registry::unit(ch.quantity),
                    value,
                    value_state,
                    reason_code,
                }
            })
        })
        .collect();
    let flags: Vec<_> = registry::flags(ch.quantity)
        .iter()
        .filter_map(|(suffix, kind)| {
            fields.get(&format!("{}_{suffix}", ch.base)).map(|v| {
                let state = match v.as_f64() {
                    Some(0.) => HardwareSensorFlagStateV1::Clear,
                    Some(1.) => HardwareSensorFlagStateV1::Asserted,
                    _ => HardwareSensorFlagStateV1::Malformed,
                };
                HardwareSensorFlagV1 {
                    kind: *kind,
                    state,
                    reason_code: (state == HardwareSensorFlagStateV1::Malformed)
                        .then_some(HardwareSensorReasonV1::HardwareSensorFlagInvalid),
                }
            })
        })
        .collect();
    if value.is_some()
        && flags.iter().any(|f| {
            f.kind == HardwareSensorFlagKindV1::Fault
                && f.state == HardwareSensorFlagStateV1::Asserted
        })
    {
        value_state = HardwareSensorValueStateV1::Faulted;
        reason_code = Some(HardwareSensorReasonV1::HardwareSensorFaultAsserted);
    }
    let identity =
        serde_json::to_vec(&(provider_id, chip, field)).expect("string tuple serializes");
    let sensor_id = format!("hardware-sensor:{:x}", Sha256::digest(identity));
    Ok(HardwareSensorReadingV1 {
        sensor_id,
        provider_id: provider_id.to_owned(),
        chip_id: chip.to_owned(),
        channel_id: field.to_owned(),
        raw_label: label.to_owned(),
        evidence_target: target.clone(),
        quantity: ch.quantity,
        unit: registry::unit(ch.quantity),
        measurement_kind: ch.kind,
        value,
        value_state,
        reason_code,
        observed_at: observed_at.to_owned(),
        limits,
        flags,
    })
}

fn check_string(s: &str) -> Result<(), SensorError> {
    if s.trim().is_empty() || s.len() > MAX_HARDWARE_SENSOR_STRING_BYTES {
        Err(SensorError::new(
            HardwareSensorReasonV1::HardwareSensorStructureLimit,
            "hardware_sensor_normalize",
        ))
    } else {
        Ok(())
    }
}
