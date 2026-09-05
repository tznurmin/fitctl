// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Schema for standalone target-bound thermal evidence artifacts.

use serde::{Deserialize, Serialize};

use crate::artifacts::envelope_v1::ArtifactEnvelopeV1;
use crate::artifacts::state_v1::HostStateThermalResourcesV1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Thermal resources collected as evidence for a declared target host.
///
/// This artifact intentionally carries only thermal evidence. It is not a replacement for
/// `host-state.v2` and cannot satisfy non-thermal runtime requirements.
pub struct ThermalEvidenceV1 {
    pub envelope: ArtifactEnvelopeV1,
    pub thermal_evidence: HostStateThermalResourcesV1,
}
