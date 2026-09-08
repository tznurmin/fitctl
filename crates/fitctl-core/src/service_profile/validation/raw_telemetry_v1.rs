// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Raw reliability and thermal requirement constraints.

use super::helpers_v1::{
    reject_explicit_nulls, reject_unknown_keys, validate_non_blank_string_json, validate_u64_json,
};
use crate::service_profile::{ServiceProfileError, ServiceProfileErrorCode};
use serde_json::{Map, Value};

pub(super) fn validate_reliability_json(
    requirements: &Map<String, Value>,
) -> Result<(), ServiceProfileError> {
    if let Some(memory_reliability) = requirements.get("required_memory_reliability") {
        let memory_reliability = memory_reliability.as_object().ok_or_else(|| {
            ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileDocumentInvalid,
                "profile_decode",
                "service profile required_memory_reliability must be an object",
            )
        })?;
        reject_unknown_keys(
            memory_reliability,
            &[
                "require_provider_success",
                "max_corrected_error_count",
                "max_uncorrected_error_count",
            ],
        )?;
        reject_explicit_nulls(
            memory_reliability,
            &[
                "require_provider_success",
                "max_corrected_error_count",
                "max_uncorrected_error_count",
            ],
            "service profile required_memory_reliability field",
        )?;
        validate_u64_json(
            memory_reliability.get("max_corrected_error_count"),
            "required memory reliability max_corrected_error_count",
        )?;
        validate_u64_json(
            memory_reliability.get("max_uncorrected_error_count"),
            "required memory reliability max_uncorrected_error_count",
        )?;
    }
    if let Some(gpu_reliability) = requirements.get("required_gpu_reliability") {
        let gpu_reliability = gpu_reliability.as_object().ok_or_else(|| {
            ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileDocumentInvalid,
                "profile_decode",
                "service profile required_gpu_reliability must be an object",
            )
        })?;
        reject_unknown_keys(
            gpu_reliability,
            &[
                "require_provider_success",
                "require_ecc_mode_current",
                "max_volatile_corrected_ecc_error_count",
                "max_volatile_uncorrected_ecc_error_count",
                "require_no_retired_pages_pending",
                "require_no_row_remapper_pending",
            ],
        )?;
        reject_explicit_nulls(
            gpu_reliability,
            &[
                "require_provider_success",
                "require_ecc_mode_current",
                "max_volatile_corrected_ecc_error_count",
                "max_volatile_uncorrected_ecc_error_count",
                "require_no_retired_pages_pending",
                "require_no_row_remapper_pending",
            ],
            "service profile required_gpu_reliability field",
        )?;
        validate_non_blank_string_json(
            gpu_reliability.get("require_ecc_mode_current"),
            "required GPU reliability require_ecc_mode_current",
        )?;
        validate_u64_json(
            gpu_reliability.get("max_volatile_corrected_ecc_error_count"),
            "required GPU reliability max_volatile_corrected_ecc_error_count",
        )?;
        validate_u64_json(
            gpu_reliability.get("max_volatile_uncorrected_ecc_error_count"),
            "required GPU reliability max_volatile_uncorrected_ecc_error_count",
        )?;
    }
    Ok(())
}

pub(super) fn validate_thermal_json(
    requirements: &Map<String, Value>,
) -> Result<(), ServiceProfileError> {
    if let Some(required_thermal_sensors) = requirements.get("required_thermal_sensors") {
        let required_thermal_sensors = required_thermal_sensors.as_array().ok_or_else(|| {
            ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileDocumentInvalid,
                "profile_decode",
                "service profile required_thermal_sensors must be an array",
            )
        })?;
        for (index, requirement) in required_thermal_sensors.iter().enumerate() {
            let requirement = requirement.as_object().ok_or_else(|| {
                ServiceProfileError::new(
                    ServiceProfileErrorCode::ServiceProfileDocumentInvalid,
                    "profile_decode",
                    format!(
                        "service profile required_thermal_sensors entry at index {index} must be an object"
                    ),
                )
            })?;
            reject_unknown_keys(
                requirement,
                &[
                    "requirement_id",
                    "provider_id",
                    "sensor_id",
                    "sensor_alias",
                    "sensor_role",
                    "max_temperature_millidegrees_celsius",
                    "require_provider_success",
                ],
            )?;
            reject_explicit_nulls(
                requirement,
                &[
                    "requirement_id",
                    "provider_id",
                    "sensor_id",
                    "sensor_alias",
                    "sensor_role",
                    "max_temperature_millidegrees_celsius",
                    "require_provider_success",
                ],
                "service profile required_thermal_sensors field",
            )?;
        }
    }

    Ok(())
}
