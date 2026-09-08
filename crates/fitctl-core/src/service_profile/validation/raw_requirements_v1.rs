// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Validate the core requirement map in existing field-check order.

use super::helpers_v1::{reject_explicit_nulls, reject_unknown_keys, require_object};
use super::raw_storage_v1::{validate_path_relationships_json, validate_paths_json};
use super::raw_telemetry_v1::{validate_reliability_json, validate_thermal_json};
use crate::service_profile::ServiceProfileError;
use serde_json::{Map, Value};

pub(super) fn validate_requirements_json(
    profile: &Map<String, Value>,
) -> Result<(), ServiceProfileError> {
    let requirements = require_object(
        profile,
        "core_requirements",
        "service profile core requirements",
    )?;
    reject_unknown_keys(
        requirements,
        &[
            "primary_capability_class",
            "allowed_visibility_scopes",
            "min_allocatable_cpu_logical_cores",
            "min_allocatable_memory_bytes",
            "min_non_loopback_interfaces",
            "min_network_link_speed_mbps",
            "required_network_interface_kinds",
            "min_numa_nodes",
            "max_numa_nodes",
            "min_cpu_packages",
            "min_policy_scoped_accelerators",
            "require_accelerator_locality_known",
            "max_accelerator_numa_nodes",
            "required_paths",
            "path_relationships",
            "required_path_link_pairs",
            "required_thermal_sensors",
            "required_memory_reliability",
            "required_gpu_reliability",
        ],
    )?;
    reject_explicit_nulls(
        requirements,
        &[
            "primary_capability_class",
            "allowed_visibility_scopes",
            "min_allocatable_cpu_logical_cores",
            "min_allocatable_memory_bytes",
            "min_non_loopback_interfaces",
            "min_network_link_speed_mbps",
            "required_network_interface_kinds",
            "min_numa_nodes",
            "max_numa_nodes",
            "min_cpu_packages",
            "min_policy_scoped_accelerators",
            "require_accelerator_locality_known",
            "max_accelerator_numa_nodes",
            "required_paths",
            "path_relationships",
            "required_path_link_pairs",
            "required_thermal_sensors",
            "required_memory_reliability",
            "required_gpu_reliability",
        ],
        "service profile requirement field",
    )?;
    validate_paths_json(requirements)?;
    validate_reliability_json(requirements)?;
    validate_path_relationships_json(requirements)?;
    validate_thermal_json(requirements)?;
    Ok(())
}
