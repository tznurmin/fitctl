// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

// Positive control: the same compiler context must load and type-check the current public API.
use fitctl_core::artifacts::state_v1::HostStateCoreV1;

pub fn reconstruct(old: HostStateCoreV1) -> HostStateCoreV1 {
    HostStateCoreV1 {
        collectors: old.collectors,
        section_metadata: old.section_metadata,
        freshness: old.freshness,
        resources: old.resources,
        path_resources: old.path_resources,
        thermal_resources: old.thermal_resources,
        hardware_sensor_resources: old.hardware_sensor_resources,
        memory_reliability: old.memory_reliability,
        gpu_reliability: old.gpu_reliability,
        boundaries: old.boundaries,
        topology: old.topology,
        operability: old.operability,
    }
}
