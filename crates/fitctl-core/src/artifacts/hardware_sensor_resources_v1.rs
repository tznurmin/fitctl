// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Opt-in electrical, fan and supporting hardware observations, never a health verdict.

use super::state_v1::{
    HostStateThermalCollectorHostV1, HostStateThermalEvidenceTargetV1,
    StateEvidenceProviderOutcomeV1,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardwareSensorResourcesV1 {
    pub observed_at: String,
    pub collector_host: HostStateThermalCollectorHostV1,
    pub providers: Vec<HardwareSensorProviderV1>,
    pub readings: Vec<HardwareSensorReadingV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardwareSensorProviderV1 {
    pub provider_id: String,
    pub provider_kind: HardwareSensorProviderKindV1,
    pub outcome: StateEvidenceProviderOutcomeV1,
    pub evidence_target: HostStateThermalEvidenceTargetV1,
    pub observed_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<HardwareSensorReasonV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwareSensorProviderKindV1 {
    LmSensorsJson,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardwareSensorReadingV1 {
    pub sensor_id: String,
    pub provider_id: String,
    pub chip_id: String,
    pub channel_id: String,
    pub raw_label: String,
    pub evidence_target: HostStateThermalEvidenceTargetV1,
    pub quantity: HardwareSensorQuantityV1,
    pub unit: HardwareSensorUnitV1,
    pub measurement_kind: HardwareSensorMeasurementKindV1,
    #[serde(deserialize_with = "nullable_value")]
    pub value: Option<i64>,
    pub value_state: HardwareSensorValueStateV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<HardwareSensorReasonV1>,
    pub observed_at: String,
    pub limits: Vec<HardwareSensorLimitV1>,
    pub flags: Vec<HardwareSensorFlagV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwareSensorQuantityV1 {
    Voltage,
    Current,
    Power,
    FanSpeed,
    Energy,
    RelativeHumidity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwareSensorUnitV1 {
    Microvolts,
    Microamperes,
    Microwatts,
    MillirevolutionsPerMinute,
    Microjoules,
    Millipercent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwareSensorMeasurementKindV1 {
    Input,
    Average,
    Counter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwareSensorValueStateV1 {
    Observed,
    Faulted,
    Unavailable,
    Malformed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardwareSensorLimitV1 {
    pub kind: HardwareSensorLimitKindV1,
    pub source: HardwareSensorLimitSourceV1,
    pub quantity: HardwareSensorQuantityV1,
    pub unit: HardwareSensorUnitV1,
    #[serde(deserialize_with = "nullable_value")]
    pub value: Option<i64>,
    pub value_state: HardwareSensorValueStateV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<HardwareSensorReasonV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwareSensorLimitKindV1 {
    Min,
    Max,
    Lcrit,
    Crit,
    AverageMin,
    AverageMax,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwareSensorLimitSourceV1 {
    ProviderReported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardwareSensorFlagV1 {
    pub kind: HardwareSensorFlagKindV1,
    pub state: HardwareSensorFlagStateV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<HardwareSensorReasonV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwareSensorFlagKindV1 {
    Alarm,
    MinAlarm,
    MaxAlarm,
    LcritAlarm,
    CritAlarm,
    CapAlarm,
    Fault,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwareSensorFlagStateV1 {
    Asserted,
    Clear,
    Unavailable,
    Malformed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwareSensorReasonV1 {
    HardwareSensorSourceUnavailable,
    HardwareSensorPermissionDenied,
    HardwareSensorCommandFailed,
    HardwareSensorTimeout,
    HardwareSensorOutputLimit,
    HardwareSensorJsonMalformed,
    HardwareSensorDuplicateKey,
    HardwareSensorValueInvalid,
    HardwareSensorValueOutOfRange,
    HardwareSensorFlagInvalid,
    HardwareSensorValueUnavailable,
    HardwareSensorFaultAsserted,
    HardwareSensorStructureLimit,
    HardwareSensorNoSupportedReadings,
    HardwareSensorSchemaInvalid,
    HardwareSensorQuantityUnitMismatch,
    HardwareSensorIdentityMismatch,
}

fn nullable_value<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<i64>, D::Error> {
    Option::<i64>::deserialize(deserializer)
}
