// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Presentation-only hardware quantities; provider alarms are not fitctl health verdicts.

use super::*;
use crate::artifacts::hardware_sensor_resources_v1::*;

pub(super) fn render(
    output: &mut String,
    sensors: &HardwareSensorResourcesV1,
    options: InspectRenderOptionsV1,
) -> Result<(), InspectError> {
    push_summary_group_separator(output)?;
    push_summary_group_header(output, "Hardware Sensors")?;
    push_summary_group_line(
        output,
        "Observed at",
        format_timestamp_for_inspect(&sensors.observed_at, options),
    )?;
    for p in &sensors.providers {
        push_summary_group_line(
            output,
            &format!("Provider {}", p.provider_id),
            format!(
                "{}; {:?}; target {:?}",
                p.outcome.as_str(),
                p.reason_code,
                p.evidence_target
            ),
        )?;
    }
    for r in &sensors.readings {
        push_summary_group_line(
            output,
            &format!("Reading {}", r.sensor_id),
            format!(
                "{}; {:?} {:?}; {}; {:?}; provider {}",
                r.raw_label,
                r.quantity,
                r.measurement_kind,
                measurement(r.value, r.unit),
                r.value_state,
                r.provider_id
            ),
        )?;
        for limit in &r.limits {
            push_summary_group_line(
                output,
                "Provider limit",
                format!(
                    "{:?}: {}; {:?}",
                    limit.kind,
                    measurement(limit.value, limit.unit),
                    limit.value_state
                ),
            )?;
        }
        for flag in &r.flags {
            push_summary_group_line(
                output,
                "Provider flag",
                format!("{:?}: {:?}", flag.kind, flag.state),
            )?;
        }
    }
    Ok(())
}

fn measurement(value: Option<i64>, unit: HardwareSensorUnitV1) -> String {
    let (scale, symbol) = match unit {
        HardwareSensorUnitV1::Microvolts => (1_000_000., "V"),
        HardwareSensorUnitV1::Microamperes => (1_000_000., "A"),
        HardwareSensorUnitV1::Microwatts => (1_000_000., "W"),
        HardwareSensorUnitV1::Microjoules => (1_000_000., "J"),
        HardwareSensorUnitV1::MillirevolutionsPerMinute => (1000., "RPM"),
        HardwareSensorUnitV1::Millipercent => (1000., "%RH"),
    };
    value
        .map(|v| format!("{:.6} {symbol}", v as f64 / scale))
        .unwrap_or_else(|| format!("unavailable {symbol}"))
}
