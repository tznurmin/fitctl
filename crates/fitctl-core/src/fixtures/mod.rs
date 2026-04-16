// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Shared fixture coverage tags used by replay corpora and regression metadata.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureCoverageTagV1 {
    BareMetalLike,
    VmLike,
    ContainerRestricted,
    LimitedPrivilege,
    FullPrivilege,
    UnknownVisibility,
    X86_64,
    Aarch64,
    Wifi,
    MixedVirtualNetwork,
    NetworkOdd,
    DiscreteGpu,
    IntegratedGraphics,
    NoAccelerators,
    StorageOdd,
    ArmCpuFallback,
    FreshState,
    StaleState,
    CgroupLimited,
    RuntimeCollectorGap,
}
