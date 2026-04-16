// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Typed host-contract payload structures consumed by validation and inspect rendering.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::artifacts::metadata_v1::IdentitySummaryV1;
use crate::policy::capability_classes_v1::DerivedCapabilityClaimV1;
use crate::survey::{
    AcceleratorKindV1, AcceleratorOperabilityV1, NetworkInterfaceKindV1, StaticOperabilityV1,
    StorageBlockDeviceClassV1,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
/// Policy-shaped host promise consumed by validation.
///
/// Core and extension contracts stay separate so the base schema can remain stable while
/// namespace-specific sections evolve independently.
pub struct HostContractPayloadV1 {
    #[serde(default)]
    pub core_contract: HostContractCoreV1,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extension_contract: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
/// Core host promise that validation can reason about without extension-specific logic.
pub struct HostContractCoreV1 {
    #[serde(default)]
    pub capability_classes: BTreeMap<String, DerivedCapabilityClaimV1>,
    #[serde(default)]
    pub execution_constraints: ExecutionConstraintsV1,
    #[serde(default)]
    pub identity_summary: IdentitySummaryV1,
    #[serde(default)]
    pub network_summary: ContractNetworkSummaryV1,
    #[serde(default, skip_serializing_if = "ContractStorageSummaryV1::is_empty")]
    pub storage_summary: ContractStorageSummaryV1,
    #[serde(
        default,
        skip_serializing_if = "ContractAcceleratorSummaryV1::is_empty"
    )]
    pub accelerator_summary: ContractAcceleratorSummaryV1,
    #[serde(default)]
    pub topology_summary: ContractTopologySummaryV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Environmental facts that constrain what the host is allowed to claim.
pub struct ExecutionConstraintsV1 {
    pub visibility_scope: crate::survey::VisibilityScopeV1,
    pub container_runtime: Option<String>,
}

impl Default for ExecutionConstraintsV1 {
    fn default() -> Self {
        Self {
            visibility_scope: crate::survey::VisibilityScopeV1::Unknown,
            container_runtime: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
/// Coarse topology summary used for admission decisions rather than full topology replay.
pub struct ContractTopologySummaryV1 {
    #[serde(default)]
    pub numa_nodes: Option<u32>,
    #[serde(default)]
    pub cpu_packages: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
/// Conservative network summary promoted into contract semantics.
pub struct ContractNetworkSummaryV1 {
    #[serde(default)]
    pub total_interfaces: Option<u32>,
    #[serde(default)]
    pub non_loopback_interfaces: Option<u32>,
    #[serde(default)]
    pub interface_kinds: Vec<NetworkInterfaceKindV1>,
    #[serde(default)]
    pub max_observed_speed_mbps: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operability: Option<ContractNetworkOperabilityV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Static network operability summary.
///
/// Runtime link readiness belongs in host-state rather than the contract.
pub struct ContractNetworkOperabilityV1 {
    pub static_operability: StaticOperabilityV1,
    pub physical_non_loopback_interfaces: u32,
    pub interfaces_with_known_speed: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
/// Conservative storage summary promoted into contract semantics.
pub struct ContractStorageSummaryV1 {
    #[serde(default)]
    pub total_block_devices: Option<u32>,
    #[serde(default)]
    pub total_mounts: Option<u32>,
    #[serde(default)]
    pub block_device_classes: Vec<StorageBlockDeviceClassV1>,
    #[serde(default)]
    pub filesystem_types: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operability: Option<ContractStorageOperabilityV1>,
}

impl ContractStorageSummaryV1 {
    fn is_empty(&self) -> bool {
        self.total_block_devices.is_none()
            && self.total_mounts.is_none()
            && self.block_device_classes.is_empty()
            && self.filesystem_types.is_empty()
            && self.operability.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Static storage operability summary, not a health or performance model.
pub struct ContractStorageOperabilityV1 {
    pub static_operability: StaticOperabilityV1,
    pub usable_block_devices: u32,
    pub root_mount_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
/// Coarse accelerator summary promoted when it materially affects host promise.
pub struct ContractAcceleratorSummaryV1 {
    #[serde(default)]
    pub total_accelerators: Option<u32>,
    #[serde(default)]
    pub gpu_accelerators: Option<u32>,
    #[serde(default)]
    pub accelerator_kinds: Vec<AcceleratorKindV1>,
    #[serde(default)]
    pub vendors: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operability: Option<AcceleratorOperabilityV1>,
}

impl ContractAcceleratorSummaryV1 {
    fn is_empty(&self) -> bool {
        self.total_accelerators.is_none()
            && self.gpu_accelerators.is_none()
            && self.accelerator_kinds.is_empty()
            && self.vendors.is_empty()
            && self.operability.is_none()
    }
}
