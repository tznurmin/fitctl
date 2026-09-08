// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Known extension requirement cross-field checks.

use crate::artifacts::service_profile_v1::ServiceProfileV1;
use crate::extensions::{
    decode_cuda_runtime_requirement_from_value, CudaRuntimeRequirementV1, CUDA_RUNTIME_NAMESPACE,
};
use crate::service_profile::{ServiceProfileError, ServiceProfileErrorCode};

pub(super) fn validate_known_extension_requirement_semantics(
    profile: &ServiceProfileV1,
) -> Result<(), ServiceProfileError> {
    let payload = &profile.profile;

    if let Some(value) = payload.extension_requirements.get(CUDA_RUNTIME_NAMESPACE) {
        let requirement = decode_cuda_runtime_requirement_from_value(value).map_err(|error| {
            ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileArtifactInvalid,
                "profile_validate",
                format!(
                    "service profile CUDA runtime extension requirement is invalid: {}",
                    error.message
                ),
            )
        })?;
        validate_cuda_runtime_requirement_semantics(requirement, payload)?;
    }

    Ok(())
}

fn validate_cuda_runtime_requirement_semantics(
    requirement: CudaRuntimeRequirementV1,
    payload: &crate::artifacts::service_profile_v1::ServiceProfilePayloadV1,
) -> Result<(), ServiceProfileError> {
    if requirement
        .minimum_qualifying_device_aggregate_allocatable_memory_bytes
        .is_some()
        && payload
            .core_requirements
            .min_policy_scoped_accelerators
            .is_none()
    {
        return Err(ServiceProfileError::new(
            ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
            "profile_validate",
            "CUDA qualifying-device aggregate allocatable-memory thresholds require core_requirements.min_policy_scoped_accelerators",
        ));
    }

    Ok(())
}
