// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Strip observation-time/display volatility without dropping quantity validity or target identity.

use super::hardware_sensor_resources_v1::HardwareSensorResourcesV1;

pub(crate) fn projection(s: &HardwareSensorResourcesV1) -> HardwareSensorResourcesV1 {
    let mut s = s.clone();
    s.observed_at.clear();
    for p in &mut s.providers {
        p.observed_at.clear();
        p.diagnostics = None;
    }
    for r in &mut s.readings {
        r.observed_at.clear();
        r.raw_label.clear();
        r.limits.sort_by_key(|l| format!("{:?}", l.kind));
        r.flags.sort_by_key(|f| format!("{:?}", f.kind));
    }
    s.providers
        .sort_by(|a, b| a.provider_id.cmp(&b.provider_id));
    s.readings.sort_by(|a, b| a.sensor_id.cmp(&b.sensor_id));
    s
}
