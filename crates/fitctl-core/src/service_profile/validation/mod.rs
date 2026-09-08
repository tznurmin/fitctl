// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Shared specialized service-profile validation.

mod extensions_v1;
mod helpers_v1;
mod raw_requirements_v1;
mod raw_storage_v1;
mod raw_telemetry_v1;
mod raw_v1;
mod requirements_v1;
mod semantics_v1;

pub(super) use raw_v1::validate_service_profile_json;
pub(super) use semantics_v1::validate_service_profile_semantics;
