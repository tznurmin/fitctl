// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Closed string vocabularies retained for wire compatibility.

pub(crate) const THERMAL_PROVIDER_COMMAND_FAILED: &str = "thermal_provider_command_failed";
pub(crate) const THERMAL_PROVIDER_COMMAND_TIMEOUT: &str = "thermal_provider_command_timeout";
pub(crate) const THERMAL_PROVIDER_UNAVAILABLE: &str = "thermal_provider_unavailable";
pub(crate) const THERMAL_PROVIDER_PERMISSION_DENIED: &str = "thermal_provider_permission_denied";
pub(crate) const THERMAL_PROVIDER_OUTPUT_TOO_LARGE: &str = "thermal_provider_output_too_large";
pub(crate) const THERMAL_PROVIDER_OUTPUT_MALFORMED: &str = "thermal_provider_output_malformed";
pub(crate) const THERMAL_PROVIDER_NO_TEMPERATURE_READINGS: &str =
    "thermal_provider_no_temperature_readings";

pub(crate) const EDAC_SYSFS_UNAVAILABLE: &str = "edac_sysfs_unavailable";
pub(crate) const EDAC_SYSFS_READ_FAILED: &str = "edac_sysfs_read_failed";
pub(crate) const EDAC_SYSFS_NO_CONTROLLERS: &str = "edac_sysfs_no_controllers";
pub(crate) const EDAC_SYSFS_PARTIAL: &str = "edac_sysfs_partial";

pub(crate) const NVIDIA_SMI_NO_DEVICES: &str = "nvidia_smi_no_devices";
pub(crate) const NVIDIA_SMI_XML_MALFORMED: &str = "nvidia_smi_xml_malformed";
pub(crate) const NVIDIA_SMI_COMMAND_FAILED: &str = "nvidia_smi_command_failed";
pub(crate) const NVIDIA_SMI_UNAVAILABLE: &str = "nvidia_smi_unavailable";

pub(crate) fn is_supported_survey_collection_mode(value: &str) -> bool {
    matches!(value, "live" | "replay")
}

pub(crate) fn is_supported_thermal_provider_error_code(value: &str) -> bool {
    [
        THERMAL_PROVIDER_COMMAND_FAILED,
        THERMAL_PROVIDER_COMMAND_TIMEOUT,
        THERMAL_PROVIDER_UNAVAILABLE,
        THERMAL_PROVIDER_PERMISSION_DENIED,
        THERMAL_PROVIDER_OUTPUT_TOO_LARGE,
        THERMAL_PROVIDER_OUTPUT_MALFORMED,
        THERMAL_PROVIDER_NO_TEMPERATURE_READINGS,
    ]
    .contains(&value)
}

pub(crate) fn is_supported_memory_provider_error_code(value: &str) -> bool {
    [
        EDAC_SYSFS_UNAVAILABLE,
        EDAC_SYSFS_READ_FAILED,
        EDAC_SYSFS_NO_CONTROLLERS,
        EDAC_SYSFS_PARTIAL,
    ]
    .contains(&value)
}

pub(crate) fn is_supported_gpu_provider_error_code(value: &str) -> bool {
    [
        NVIDIA_SMI_NO_DEVICES,
        NVIDIA_SMI_XML_MALFORMED,
        NVIDIA_SMI_COMMAND_FAILED,
        NVIDIA_SMI_UNAVAILABLE,
    ]
    .contains(&value)
}
