// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Closed libsensors channel registry. JSON values are SI values, not raw sysfs integers.

use crate::artifacts::hardware_sensor_resources_v1::*;
use serde_json::Value;

pub(crate) struct Channel {
    pub base: String,
    pub quantity: HardwareSensorQuantityV1,
    pub kind: HardwareSensorMeasurementKindV1,
}

pub(crate) fn channel(field: &str) -> Option<Channel> {
    let (base, suffix) = field.split_once('_')?;
    let (quantity, index, allow_zero) = [
        ("in", HardwareSensorQuantityV1::Voltage, true),
        ("curr", HardwareSensorQuantityV1::Current, false),
        ("power", HardwareSensorQuantityV1::Power, false),
        ("fan", HardwareSensorQuantityV1::FanSpeed, false),
        ("energy", HardwareSensorQuantityV1::Energy, false),
        (
            "humidity",
            HardwareSensorQuantityV1::RelativeHumidity,
            false,
        ),
    ]
    .into_iter()
    .find_map(|(prefix, quantity, zero)| base.strip_prefix(prefix).map(|i| (quantity, i, zero)))?;
    if index.is_empty()
        || !index.bytes().all(|b| b.is_ascii_digit())
        || (index.starts_with('0') && !(allow_zero && index == "0"))
    {
        return None;
    }
    let kind = match suffix {
        "input" if quantity == HardwareSensorQuantityV1::Energy => {
            HardwareSensorMeasurementKindV1::Counter
        }
        "input" => HardwareSensorMeasurementKindV1::Input,
        "average" if quantity == HardwareSensorQuantityV1::Power => {
            HardwareSensorMeasurementKindV1::Average
        }
        _ => return None,
    };
    Some(Channel {
        base: base.to_owned(),
        quantity,
        kind,
    })
}

pub(crate) fn unit(q: HardwareSensorQuantityV1) -> HardwareSensorUnitV1 {
    use HardwareSensorQuantityV1::*;
    match q {
        Voltage => HardwareSensorUnitV1::Microvolts,
        Current => HardwareSensorUnitV1::Microamperes,
        Power => HardwareSensorUnitV1::Microwatts,
        FanSpeed => HardwareSensorUnitV1::MillirevolutionsPerMinute,
        Energy => HardwareSensorUnitV1::Microjoules,
        RelativeHumidity => HardwareSensorUnitV1::Millipercent,
    }
}

pub(crate) fn value_valid(q: HardwareSensorQuantityV1, value: i64) -> bool {
    match q {
        HardwareSensorQuantityV1::FanSpeed | HardwareSensorQuantityV1::Energy => value >= 0,
        HardwareSensorQuantityV1::RelativeHumidity => (0..=100_000).contains(&value),
        _ => true,
    }
}

pub(crate) fn scaled(
    value: &Value,
    q: HardwareSensorQuantityV1,
) -> Result<i64, HardwareSensorReasonV1> {
    let value = value
        .as_f64()
        .filter(|v| v.is_finite())
        .ok_or(HardwareSensorReasonV1::HardwareSensorValueInvalid)?;
    let scale = match q {
        HardwareSensorQuantityV1::FanSpeed | HardwareSensorQuantityV1::RelativeHumidity => 1000.,
        _ => 1_000_000.,
    };
    let scaled = (value * scale).round();
    // The upper bound is exclusive: i64::MAX rounds UP to 2^63 as f64.
    if !scaled.is_finite()
        || !(-9_223_372_036_854_775_808.0..9_223_372_036_854_775_808.0).contains(&scaled)
    {
        return Err(HardwareSensorReasonV1::HardwareSensorValueOutOfRange);
    }
    let result = scaled as i64;
    if !value_valid(q, result)
        || (matches!(
            q,
            HardwareSensorQuantityV1::FanSpeed
                | HardwareSensorQuantityV1::Energy
                | HardwareSensorQuantityV1::RelativeHumidity
        ) && value < 0.)
        || (q == HardwareSensorQuantityV1::RelativeHumidity && value > 100.)
    {
        return Err(HardwareSensorReasonV1::HardwareSensorValueOutOfRange);
    }
    Ok(result)
}

pub(crate) fn limits(
    q: HardwareSensorQuantityV1,
    kind: HardwareSensorMeasurementKindV1,
) -> &'static [(&'static str, HardwareSensorLimitKindV1)] {
    use HardwareSensorLimitKindV1::*;
    match (q, kind) {
        (HardwareSensorQuantityV1::Voltage | HardwareSensorQuantityV1::Current, _) => {
            &[("min", Min), ("max", Max), ("lcrit", Lcrit), ("crit", Crit)]
        }
        (HardwareSensorQuantityV1::FanSpeed, _) => &[("min", Min), ("max", Max)],
        (HardwareSensorQuantityV1::Power, HardwareSensorMeasurementKindV1::Average) => {
            &[("average_min", AverageMin), ("average_max", AverageMax)]
        }
        (HardwareSensorQuantityV1::Power, _) => &[("max", Max), ("crit", Crit)],
        _ => &[],
    }
}

pub(crate) fn flags(
    q: HardwareSensorQuantityV1,
) -> &'static [(&'static str, HardwareSensorFlagKindV1)] {
    use HardwareSensorFlagKindV1::*;
    match q {
        HardwareSensorQuantityV1::Voltage | HardwareSensorQuantityV1::Current => &[
            ("alarm", Alarm),
            ("min_alarm", MinAlarm),
            ("max_alarm", MaxAlarm),
            ("lcrit_alarm", LcritAlarm),
            ("crit_alarm", CritAlarm),
        ],
        HardwareSensorQuantityV1::FanSpeed => &[
            ("alarm", Alarm),
            ("min_alarm", MinAlarm),
            ("max_alarm", MaxAlarm),
            ("fault", Fault),
        ],
        HardwareSensorQuantityV1::Power => &[
            ("alarm", Alarm),
            ("max_alarm", MaxAlarm),
            ("crit_alarm", CritAlarm),
            ("cap_alarm", CapAlarm),
        ],
        _ => &[],
    }
}
